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

from urllib.parse import urlparse

from ...config import settings
from ...db import supabase_admin
from ...models import (
    LLMRemediationOutput,
    RemediationPackage,
    RemediationPathway,
    ValidationMetadata,
)
from ..llm import invoke_structured_with_retry
from .classifier import classify_finding
from .confidence import compute_confidence, compute_confidence_agentic


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


# Domains considered authoritative for the agentic validation_metadata
# status/confidence heuristic. Mirrors the tier-1/2 set in web_search.py +
# confidence.py; keep in sync when adding new authoritative vendors.
_AGENT_AUTHORITATIVE_HOSTS = {
    # --- Cloud provider primary docs (Tier 1) ---
    "docs.aws.amazon.com", "aws.amazon.com",
    "docs.microsoft.com", "learn.microsoft.com",
    "cloud.google.com", "docs.oracle.com",
    # --- Standards bodies + governments (Tier 1) ---
    "cisecurity.org", "nvd.nist.gov", "csrc.nist.gov",
    "cisa.gov", "www.cisa.gov",
    "cwe.mitre.org", "capec.mitre.org", "attack.mitre.org",
    "cve.mitre.org",
    # --- Core project + community docs (Tier 2) ---
    "owasp.org", "cheatsheetseries.owasp.org",
    "kubernetes.io", "docs.kubernetes.io",
    "docs.docker.com",
    "developer.hashicorp.com", "hashicorp.com", "registry.terraform.io",
    "cert.org", "us-cert.gov",
    # --- Scanner vendor docs — canonical source for the findings we ingest ---
    "docs.prismacloud.io", "docs.paloaltonetworks.com",       # Checkov / Prisma Cloud
    "avd.aquasec.com", "docs.aquasec.com", "aquasec.com",     # Trivy (Aqua Vulnerability DB)
    "snyk.io", "security.snyk.io", "docs.snyk.io",            # Snyk
    "docs.wiz.io",                                            # Wiz
    "docs.tenable.com",                                       # Tenable / Nessus
    "www.qualys.com", "qualys.com",                           # Qualys
    "docs.github.com", "github.com",                          # GitHub advisories / security tab
    # --- OS-vendor security trackers (canonical for os_vulnerability family) ---
    "access.redhat.com", "ubuntu.com", "security-tracker.debian.org",
    "usn.ubuntu.com", "www.suse.com",
    # --- Language ecosystem advisory databases (canonical for vulnerable_dependency) ---
    "advisories.dependabot.com", "osv.dev",
    "python.org", "docs.python.org", "pypi.org",
    "nodejs.org", "npmjs.com",
    "maven.apache.org", "central.sonatype.com",
    "rubygems.org", "packagist.org",
}


def _agent_validation_metadata(pathway: RemediationPathway) -> ValidationMetadata:
    """Build ValidationMetadata from URLs the agent actually cited across the
    pathway. Called on the agentic-success path — pattern's static
    primary_sources are NOT used here.

    Status + confidence heuristic:
      validated / high    — 2+ distinct sources AND at least 1 is authoritative
      partial / medium    — 1+ source cited but only Tier-3/4
      unvalidated / low   — nothing cited (shouldn't happen post-verifier)
    """
    seen_urls: set[str] = set()
    display_sources: list[str] = []

    def _collect(step):
        if step is None:
            return
        url = getattr(step, "source_url", "") or ""
        name = getattr(step, "source", "") or ""
        if url and url not in seen_urls:
            seen_urls.add(url)
            display_sources.append(f"{name} — {url}" if name else url)

    for step in pathway.remediation_steps or []:
        _collect(step)
    if pathway.rollback_plan and pathway.rollback_plan.steps:
        for step in pathway.rollback_plan.steps:
            _collect(step)

    hosts = set()
    for u in seen_urls:
        try:
            h = urlparse(u).netloc.lower()
            if h:
                hosts.add(h)
        except Exception:  # noqa: BLE001
            pass
    authoritative_hits = hosts & _AGENT_AUTHORITATIVE_HOSTS

    if len(seen_urls) >= 2 and authoritative_hits:
        status = "validated"
        confidence = "high"
    elif seen_urls:
        status = "partial"
        confidence = "medium"
    else:
        status = "unvalidated"
        confidence = "low"

    return ValidationMetadata(
        status=status,
        sources=display_sources[:20],
        timestamp=datetime.now(UTC).isoformat(),
        confidence=confidence,
    )


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
    """Load the sub-agent-3 v1.4 (HYBRID pattern-based) prompt row.

    Explicitly selects v1.4 because both v1.4 (hybrid) and v2.0 (agentic)
    are active in prompt_db after migration 0048 — this function is called
    by the hybrid fallback path and needs the pattern-adaptation prompt.
    The agentic path uses a separate loader in agent_v2._load_prompt_v2.
    """
    resp = (
        sb.table("prompt_db")
        .select("agent,version,model,prompt_text,parameters")
        .eq("agent", "sub-agent-3")
        .eq("version", "v1.4")
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        raise RuntimeError(
            "No sub-agent-3 v1.4 prompt row in prompt_db. "
            "Apply migration 0047_sub_agent_3_prompt_v1_4.sql."
        )
    return rows[0]


def _issue_payload(issue: dict) -> dict:
    """Trim the issue row to the fields Sub-Agent 3 actually uses.

    Includes two upstream-derived hints:
      solution              — scanner-provided remediation text (Sub-Agent 1
                              extracts this from raw scanner output when
                              present: Snyk `remediation`, Trivy `FixedVersion`,
                              Tenable/Qualys `solution`, etc.).
      remediation_suggestion — Sub-Agent 2's LLM-generated summary derived
                              from the whole enriched context.

    Sub-Agent 3's prompt (v1.4+) treats these as ADDITIONAL CONTEXT — the
    curated pattern from remediation_patterns remains authoritative for
    rollback / test scripts / sources. Hints inform placeholder filling and
    can align/override when they don't conflict with the pattern.
    """
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
        # Upstream hints (v1.4)
        "solution": issue.get("solution"),
        "remediation_suggestion": issue.get("remediation_suggestion"),
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

    # Fetch raw_finding so the classifier can use raw.resource for
    # deterministic Checkov-style classification. Cheap single-row lookup.
    raw: dict | None = None
    if issue.get("raw_finding_id") is not None:
        raw_resp = (
            sb.table("raw_findings")
            .select("raw")
            .eq("id", issue["raw_finding_id"])
            .limit(1)
            .execute()
        )
        if raw_resp.data:
            raw = raw_resp.data[0].get("raw") or {}

    family = classify_finding(issue, raw=raw)
    if family == "unknown":
        raise ValueError(
            f"Issue {issue.get('id')} did not classify into a known family. "
            f"source={issue.get('source')} cwe={issue.get('cwe_id')} purl={issue.get('runtime_purl')}"
        )

    asset = _load_asset(sb, issue)

    # --- Try the AGENTIC path first (Phase-2 default when Tavily key set) ---
    # Agent researches from live authoritative sources (AWS/CIS/NVD/CISA docs).
    # NO pattern loaded on this path — validation_metadata + confidence derive
    # from what the agent actually cited + what the verifier observed.
    # If the agent fails / hits budget cap / produces invalid output, we fall
    # through to the hybrid pattern-based path.
    agent_result = None  # tuple (LLMRemediationOutput, VerificationReport) | None
    if settings.tavily_api_key:
        from ..trace import emit_trace  # noqa: PLC0415 (defer import — circular)
        from .agent_v2 import run_agentic_planner  # noqa: PLC0415
        try:
            agent_result = run_agentic_planner(
                issue=issue,
                asset=asset,
                family=family,
                run_id=run_id,
                sb_pub=sb,
                emit_fn=emit_trace,
            )
        except Exception as e:  # noqa: BLE001
            emit_trace(
                run_id, "sub-agent-3", "ERROR",
                f"Agentic planner raised, falling back to hybrid: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )

    if agent_result is not None:
        # --- AGENT SUCCESS PATH — no pattern used. All authority from live research. ---
        llm_output, verification_report = agent_result
        enriched_pathways: list[RemediationPathway] = []
        for pathway in llm_output.pathways:
            pathway.validation_metadata = _agent_validation_metadata(pathway)
            confidence = compute_confidence_agentic(
                issue=issue,
                asset=asset,
                pathway=pathway,
                verification_report=verification_report,
            )
            pathway.confidence_score = confidence["score"]
            pathway.confidence_components = confidence["components"]
            enriched_pathways.append(pathway)
    else:
        # --- HYBRID FALLBACK — pattern-based (v1.4 prompt + pattern adaptation) ---
        from ..trace import emit_trace  # noqa: PLC0415
        emit_trace(
            run_id, "sub-agent-3", "MESSAGE",
            "Using hybrid pattern-based planner (v1.4)",
        )
        pattern = _load_pattern(sb, family)
        if pattern is None:
            raise RuntimeError(
                f"No row in remediation_patterns for family='{family}' AND agent path unavailable. "
                "Apply migration 0036 OR set TAVILY_API_KEY."
            )
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

        llm_output = invoke_structured_with_retry(
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

        # Attach pattern-derived validation metadata + confidence
        validation_meta = _validation_metadata_for(pattern)
        enriched_pathways = []
        for pathway in llm_output.pathways:
            confidence = compute_confidence(
                issue=issue,
                asset=asset,
                pattern=pattern,
                pathway=pathway,
                affected_asset_count=1,
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
