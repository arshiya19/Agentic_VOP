"""Knowledge Base Capture — stores successful fix outcomes for reuse.

Called by the fixer orchestrator AFTER a fix_run completes with status='success'
and all validations pass. Extracts the proven fix pattern and inserts it into
the `remediation_kb` table so SA-3 can use it as a few-shot example on future
runs targeting the same check_id/family.

Public API:
    capture_successful_fix(sb, fix_run_id, ctx, outcome) -> int | None
        Returns the new remediation_kb row id, or None if capture was skipped
        (e.g. duplicate fingerprint, missing required fields).

Design:
    - Only captures verified successes (all validation_results passed)
    - Deduplicates via finding_fingerprint (hash of check_id + resource_type + file_path)
    - If a duplicate exists, updates confidence_score if the new one is higher
    - Never blocks the main fixer flow — all errors are swallowed and logged
"""

from __future__ import annotations

import hashlib
import json
import traceback
from typing import Any

from ..fixer.models import FixContext, StrategyOutcome


# =============================================================================
# Fingerprint generation
# =============================================================================
def _compute_fingerprint(check_id: str, resource_type: str | None, file_path: str | None) -> str:
    """Deterministic hash for dedup. Same check + resource + file = same fix."""
    parts = [
        check_id or "",
        resource_type or "",
        file_path or "",
    ]
    raw = "|".join(parts).lower().strip()
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# =============================================================================
# Extract check_id from issue/package context
# =============================================================================
def _extract_check_id(ctx: FixContext) -> str | None:
    """Pull the scanner check_id from the issue or raw finding.

    Checkov → check_id (e.g. CKV_AWS_18)
    Semgrep → rule_id
    Trivy   → VulnerabilityID
    Generic → source_vuln_id from the normalized issue
    """
    issue = ctx.issue or {}

    # Direct check_id field (Checkov findings carry this)
    check_id = issue.get("source_vuln_id") or issue.get("cve_id")
    if check_id:
        return check_id

    # Look in raw finding (source_raw nested)
    raw = issue.get("source_raw") or {}
    if isinstance(raw, dict):
        return (
            raw.get("check_id")
            or raw.get("rule_id")
            or raw.get("VulnerabilityID")
            or raw.get("vuln_id")
        )

    return issue.get("title", "")[:100]  # Fallback: use title as identifier


# =============================================================================
# Extract family from package
# =============================================================================
def _extract_family(ctx: FixContext) -> str:
    """Get the remediation family from the package row."""
    pkg = ctx.package or {}
    return pkg.get("family") or "unknown"


# =============================================================================
# Build the KB entry payload
# =============================================================================
def _build_kb_row(
    ctx: FixContext,
    outcome: StrategyOutcome,
    confidence_score: int | None = None,
) -> dict[str, Any] | None:
    """Assemble the row to insert into remediation_kb.

    Returns None if required fields are missing (skip capture).
    """
    check_id = _extract_check_id(ctx)
    if not check_id:
        return None

    family = _extract_family(ctx)
    fingerprint = _compute_fingerprint(check_id, ctx.resource_name, ctx.file_path)

    # Extract remediation steps from the package pathway
    pathway = ctx.pathway or {}
    remediation_steps = pathway.get("remediation_steps") or []
    rollback_plan = pathway.get("rollback_plan") or {}
    rollback_steps = rollback_plan.get("steps") or []

    # Validation results from the outcome
    validation_results = [r.model_dump(mode="json") for r in outcome.validation_results]

    # Context fields for LLM prompt assembly
    pkg = ctx.package or {}
    finding_summary = pkg.get("finding") or ctx.issue.get("title", "")
    root_cause = pkg.get("root_cause") or ""

    return {
        "check_id": check_id,
        "family": family,
        "finding_fingerprint": fingerprint,
        "remediation_steps": json.dumps(remediation_steps)
        if isinstance(remediation_steps, list)
        else remediation_steps,
        "rollback_steps": json.dumps(rollback_steps)
        if isinstance(rollback_steps, list)
        else rollback_steps,
        "validation_results": json.dumps(validation_results),
        "finding_summary": finding_summary[:500] if finding_summary else None,
        "root_cause": root_cause[:500] if root_cause else None,
        "resource_type": ctx.resource_name,
        "scanner_type": ctx.scanner_type,
        "file_path": ctx.file_path,
        "source_fix_run_id": ctx.fix_run_id,
        "source_package_id": ctx.package_id,
        "source_issue_id": ctx.issue_id,
        "agent_run_id": ctx.agent_run_id,
        "confidence_score": confidence_score,
    }


# =============================================================================
# Public API — capture a successful fix into the knowledge base
# =============================================================================
def capture_successful_fix(
    sb: Any,
    ctx: FixContext,
    outcome: StrategyOutcome,
    *,
    confidence_score: int | None = None,
    emit_fn=None,
) -> int | None:
    """Store a proven fix in remediation_kb for future few-shot reuse.

    Guards:
        - Only captures if outcome.status == 'success'
        - Only captures if ALL validation_results passed
        - Skips if required fields (check_id) are missing
        - On duplicate fingerprint, updates confidence if higher

    Returns:
        The remediation_kb row id if inserted/updated, None if skipped.
    """
    # Guard: only successful, fully validated runs
    if outcome.status != "success":
        return None

    # Guard: all validations must have passed
    if outcome.validation_results:
        all_passed = all(v.passed for v in outcome.validation_results)
        if not all_passed:
            return None

    try:
        row = _build_kb_row(ctx, outcome, confidence_score)
        if row is None:
            return None

        fingerprint = row["finding_fingerprint"]

        # Check for existing entry with same fingerprint
        existing = (
            sb.table("remediation_kb")
            .select("id, confidence_score")
            .eq("finding_fingerprint", fingerprint)
            .eq("is_active", True)
            .limit(1)
            .execute()
        )
        existing_rows = existing.data or []

        if existing_rows:
            # Duplicate — update confidence if new score is higher
            existing_row = existing_rows[0]
            existing_id = existing_row["id"]
            existing_confidence = existing_row.get("confidence_score") or 0

            if confidence_score and confidence_score > existing_confidence:
                sb.table("remediation_kb").update(
                    {
                        "confidence_score": confidence_score,
                        "remediation_steps": row["remediation_steps"],
                        "validation_results": row["validation_results"],
                        "source_fix_run_id": row["source_fix_run_id"],
                    }
                ).eq("id", existing_id).execute()

                if emit_fn:
                    try:
                        emit_fn(
                            ctx.agent_run_id,
                            "kb-capture",
                            "MESSAGE",
                            f"Updated KB entry #{existing_id} (check={row['check_id']}) "
                            f"— confidence {existing_confidence} → {confidence_score}",
                        )
                    except Exception:  # noqa: BLE001, S110
                        pass

            return existing_id

        # New entry — insert
        resp = sb.table("remediation_kb").insert(row).execute()
        inserted = resp.data or []
        if not inserted:
            return None

        kb_id = inserted[0]["id"]

        if emit_fn:
            try:
                emit_fn(
                    ctx.agent_run_id,
                    "kb-capture",
                    "MESSAGE",
                    f"Captured fix to KB #{kb_id} (check={row['check_id']}, "
                    f"family={row['family']}, confidence={confidence_score})",
                )
            except Exception:  # noqa: BLE001, S110
                pass

        return kb_id

    except Exception as e:
        # Never block the main fixer flow — swallow and log
        print(f"[kb-capture] ERROR: {type(e).__name__}: {str(e)[:300]}")
        traceback.print_exc()
        return None


# =============================================================================
# Increment reuse counter — called by retrieval when an example is injected
# =============================================================================
def increment_reuse_count(sb: Any, kb_id: int) -> None:
    """Bump times_reused and last_used_at when an example is used in a prompt."""
    try:
        # Use RPC or raw SQL for atomic increment
        sb.table("remediation_kb").update(
            {
                "times_reused": sb.table("remediation_kb")
                .select("times_reused")
                .eq("id", kb_id)
                .limit(1)
                .execute()
                .data[0]["times_reused"]
                + 1,
                "last_used_at": "now()",
            }
        ).eq("id", kb_id).execute()
    except Exception:  # noqa: BLE001, S110
        pass  # Best-effort — don't block prompt assembly


def increment_success_count(sb: Any, kb_id: int) -> None:
    """Bump times_succeeded when a reused example led to another success."""
    try:
        current = (
            sb.table("remediation_kb").select("times_succeeded").eq("id", kb_id).limit(1).execute()
        )
        rows = current.data or []
        if rows:
            sb.table("remediation_kb").update(
                {
                    "times_succeeded": rows[0]["times_succeeded"] + 1,
                }
            ).eq("id", kb_id).execute()
    except Exception:  # noqa: BLE001, S110
        pass
