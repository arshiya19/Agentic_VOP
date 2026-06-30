"""Sub-Agent 3 — Remediation Planner.

Takes ONE issue, classifies it into a remediation family, loads the matching
pattern from the remediation_patterns table, and calls the LLM to produce a
RemediationPackage (per Phase-1 Working Model §2 — 10 fields).

The LLM only generates the dynamic prose + filled-in templates. Caller
attaches deterministic metadata (family, rollback_strategy, primary_sources,
issue_id) after the call. Confidence score + approval requirement are filled
later by the Day-4 Confidence Engine.
"""

from __future__ import annotations

import uuid
from datetime import datetime, UTC
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ...db import supabase_admin
from ...models import (
    LLMRemediationOutput,
    RemediationPackage,
    RemediationPathway,
    ValidationMetadata,
)
from ..llm import invoke_structured_with_retry
from .classifier import classify_finding
from .confidence import compute_confidence


# Per Phase-1 doc §7.1, sources are tiered. Tier 1-3 = "validated";
# Tier 4-5 = "partial"; absent = "unvalidated". For Phase-1 our patterns
# all cite multiple Tier 1-3 sources, so packages land as "validated".
_TIER_1_3_KEYWORDS = (
    "aws",
    "microsoft",
    "red hat",
    "canonical",
    "oracle",
    "vmware",
    "apache",
    "openssl",
    "nvd",
    "cve",
    "cisa",
    "kev",
    "ubuntu security",
    "debian security",
    "rhsa",
    "advisory",
)
_TIER_4_5_KEYWORDS = (
    "owasp",
    "cnc",
    "cis",
    "nist",
    "internal",
    "playbook",
)


def _classify_source_tier(source: str) -> int:
    """Returns 1 if source matches Tier 1-3 (vendor/advisory/NVD/CISA),
    4 if Tier 4-5 (project docs / OWASP / CIS), 0 if unknown."""
    s = source.lower()
    if any(k in s for k in _TIER_1_3_KEYWORDS):
        return 1
    if any(k in s for k in _TIER_4_5_KEYWORDS):
        return 4
    return 0


def _validation_metadata_for(pattern: dict) -> ValidationMetadata:
    """Build the §7.1 audit metadata from the pattern's primary_sources.

    Phase-1: we trust the pattern's curated source list (since we built the
    patterns with vendor/CIS/OWASP citations). Phase-2 could add live URL
    fetching to verify the references.
    """
    sources = list(pattern.get("primary_sources") or [])
    if not sources:
        return ValidationMetadata(
            status="unvalidated",
            sources=[],
            timestamp=datetime.now(UTC).isoformat(),
            confidence="low",
        )

    tier_1_3 = sum(1 for s in sources if _classify_source_tier(s) == 1)
    if tier_1_3 >= 2:
        status, confidence = "validated", "high"
    elif tier_1_3 == 1:
        status, confidence = "validated", "medium"
    elif sources:
        status, confidence = "partial", "medium"
    else:
        status, confidence = "unvalidated", "low"

    return ValidationMetadata(
        status=status,
        sources=sources,
        timestamp=datetime.now(UTC).isoformat(),
        confidence=confidence,
    )


def _derive_approval(score: int, priority: str | None) -> str:
    """Package-level approval policy. Mirrors confidence._derive_approval
    but operates on the recommended pathway's score."""
    priority = priority or ""
    if priority == "P0" and score < 80:
        return "multi_stage"
    if score >= 90 and priority in ("P2", "P3"):
        return "auto"
    return "single_approver"


def _load_pattern(sb, family: str) -> dict | None:
    """Fetch the remediation_patterns row for a family."""
    resp = sb.table("remediation_patterns").select("*").eq("family", family).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def _load_asset(sb, issue: dict) -> dict:
    """Resolve the asset row for an issue via the issue_with_asset view.
    Returns trimmed asset dict (only fields useful for remediation prose) or {} if unattributed.
    """
    issue_id = issue.get("id")
    if issue_id is None:
        return {}
    resp = (
        sb.table("issue_with_asset")
        .select(
            "asset_name,asset_application_name,asset_environment,asset_exposure,"
            "asset_business_criticality,asset_data_classification,asset_compliance_tags"
        )
        .eq("id", issue_id)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows or not rows[0].get("asset_name"):
        return {}
    row = rows[0]
    return {
        "name": row.get("asset_name"),
        "application_name": row.get("asset_application_name"),
        "environment": row.get("asset_environment"),
        "exposure": row.get("asset_exposure"),
        "business_criticality": row.get("asset_business_criticality"),
        "data_classification": row.get("asset_data_classification"),
        "compliance_tags": row.get("asset_compliance_tags") or [],
    }


def _load_prompt(sb) -> dict:
    """Load the active sub-agent-3 prompt row."""
    resp = (
        sb.table("prompt_db")
        .select("agent,version,model,prompt_text,parameters")
        .eq("agent", "sub-agent-3")
        .eq("is_active", True)
        .order("version", desc=True)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        raise RuntimeError("No active prompt row for agent='sub-agent-3' in prompt_db")
    return rows[0]


def _issue_payload(issue: dict) -> dict:
    """Trim the issue row to the fields Sub-Agent 3 actually uses."""
    return {
        "id": issue.get("id"),
        "source": issue.get("source"),
        "severity": issue.get("severity"),
        "priority": issue.get("priority"),
        "cve_id": issue.get("cve_id"),
        "cwe_id": issue.get("cwe_id"),
        "title": issue.get("title"),
        "description": issue.get("description"),
        "asset_identity": issue.get("asset_identity") or {},
        "package": issue.get("package"),
        "runtime_hostname": issue.get("runtime_hostname"),
        "runtime_ipv4": issue.get("runtime_ipv4"),
        "runtime_os_family": issue.get("runtime_os_family"),
        "runtime_purl": issue.get("runtime_purl"),
    }


def _pattern_payload(pattern: dict) -> dict:
    """Trim the pattern row to what Sub-Agent 3 needs."""
    return {
        "family": pattern["family"],
        "display_name": pattern["display_name"],
        "action_type": pattern["action_type"],
        "canonical_steps": pattern["canonical_steps"],
        "rollback_strategy": pattern["rollback_strategy"],
        "rollback_steps": pattern["rollback_steps"],
        "validation_tests": pattern["validation_tests"],
        "test_script_templates": pattern.get("test_script_templates") or [],
        "primary_sources": pattern["primary_sources"],
        "confidence_base": pattern["confidence_base"],
        "notes": pattern.get("notes"),
    }


def plan_remediation(
    issue: dict,
    *,
    run_id: str | None = None,
    sb: Any = None,
) -> RemediationPackage:
    """Produce a RemediationPackage for one issue.

    `issue` must be the full issues row (or issue_with_runtime row — must
    include runtime_* fields). Caller is responsible for fetching it.

    Returns a fully-populated RemediationPackage. Persistence to the
    remediation_packages table is the CALLER's responsibility (Day 5).
    """
    sb = sb or supabase_admin()
    run_id = run_id or str(uuid.uuid4())

    family = classify_finding(issue)
    if family == "unknown":
        raise ValueError(
            f"Issue {issue.get('id')} did not classify into a known family. "
            f"source={issue.get('source')} cwe={issue.get('cwe_id')} purl={issue.get('runtime_purl')}"
        )

    pattern = _load_pattern(sb, family)
    if pattern is None:
        raise RuntimeError(
            f"No row in remediation_patterns for family='{family}'. Apply migration 0036."
        )

    asset = _load_asset(sb, issue)
    prompt_row = _load_prompt(sb)
    params = prompt_row.get("parameters") or {}

    payload = {
        "issue": _issue_payload(issue),
        "asset": asset,
        "pattern": _pattern_payload(pattern),
    }

    base_temp = float(params.get("temperature", 0.3))
    max_tokens = int(params.get("max_tokens", 2500))
    primary_model = prompt_row["model"]
    fallback_model = params.get("fallback_model", "gpt-4o")

    llm_output: LLMRemediationOutput = invoke_structured_with_retry(
        run_id=run_id,
        agent="sub-agent-3",
        schema=LLMRemediationOutput,
        messages=[
            SystemMessage(content=prompt_row["prompt_text"]),
            HumanMessage(content=str(payload)),
        ],
        attempts=[
            (base_temp, primary_model, max_tokens),
            (0.5, primary_model, max_tokens + 500),
            (0.3, fallback_model, max_tokens + 1000),
        ],
    )

    # Attach validation metadata + confidence to each pathway.
    validation_meta = _validation_metadata_for(pattern)
    enriched_pathways: list[RemediationPathway] = []
    for pathway in llm_output.pathways:
        confidence = compute_confidence(
            issue=issue,
            asset=asset,
            pattern=pattern,
            pathway=pathway,
            affected_asset_count=1,  # Phase-1 single-issue packages
        )
        pathway.validation_metadata = validation_meta
        pathway.confidence_score = confidence["score"]
        pathway.confidence_components = confidence["components"]
        enriched_pathways.append(pathway)

    # Pick the recommended pathway: highest confidence wins ties go to first.
    recommended_idx = max(
        range(len(enriched_pathways)),
        key=lambda i: enriched_pathways[i].confidence_score or 0,
    )
    recommended_score = enriched_pathways[recommended_idx].confidence_score or 0

    return RemediationPackage(
        issue_id=int(issue["id"]),
        family=family,
        finding=llm_output.finding,
        root_cause=llm_output.root_cause,
        impact=llm_output.impact,
        pathways=enriched_pathways,
        recommended_pathway_index=recommended_idx,
        approval_required=_derive_approval(recommended_score, issue.get("priority")),
    )


# ---------------------------------------------------------------------------
# Persistence — Day 5
# ---------------------------------------------------------------------------


def persist_package(
    pkg: RemediationPackage,
    *,
    run_id: str | None = None,
    sb: Any = None,
    initial_status: str = "awaiting_approval",
) -> int:
    """INSERT a RemediationPackage row into `remediation_packages`.

    Returns the new package row's `id`. The package's pathways are stored as
    a single jsonb blob (each pathway retains its confidence_score,
    confidence_components, validation_metadata fields).
    """
    sb = sb or supabase_admin()
    row = {
        "issue_id": pkg.issue_id,
        "family": pkg.family,
        "finding": pkg.finding,
        "root_cause": pkg.root_cause,
        "impact": pkg.impact,
        "pathways": [p.model_dump(mode="json") for p in pkg.pathways],
        "recommended_pathway_index": pkg.recommended_pathway_index,
        "approval_required": pkg.approval_required or "single_approver",
        "status": initial_status,
        "agent_run_id": run_id,
    }
    resp = sb.table("remediation_packages").insert(row).execute()
    rows = resp.data or []
    if not rows:
        raise RuntimeError("Insert into remediation_packages returned no row")
    return int(rows[0]["id"])
