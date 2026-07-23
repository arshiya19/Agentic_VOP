"""Knowledge Base Retrieval — fetch proven fixes as few-shot examples for SA-3.

Called by the SA-3 planner (both hybrid and agentic paths) BEFORE the LLM
invocation. Queries `remediation_kb` for entries matching the current finding's
check_id or family, formats them as structured few-shot context, and increments
the reuse counter.

Public API:
    retrieve_examples(sb, check_id, family, *, max_examples=3) -> list[KBExample]
        Returns up to `max_examples` proven fixes, ranked by confidence then recency.

    format_examples_for_prompt(examples) -> str
        Formats KBExample list into a string suitable for LLM prompt injection.

Design:
    - Primary lookup: exact check_id match (strongest signal)
    - Fallback: same family (weaker but still useful for structurally similar fixes)
    - Ranked by: confidence_score DESC, success_rate DESC, last_used_at DESC
    - Only active entries (is_active=True) are returned
    - Reuse counter incremented on retrieval (tracks effectiveness)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .kb_capture import increment_reuse_count


# =============================================================================
# Data model for retrieved examples
# =============================================================================
@dataclass
class KBExample:
    """A proven fix example retrieved from the knowledge base."""

    kb_id: int
    check_id: str
    family: str
    finding_summary: str
    root_cause: str
    remediation_steps: list[dict]
    rollback_steps: list[dict]
    validation_results: list[dict]
    resource_type: str | None = None
    scanner_type: str | None = None
    file_path: str | None = None
    confidence_score: int = 0
    success_rate: float = 0.0
    times_reused: int = 0
    match_type: str = "exact"  # "exact" (check_id) or "family" (fallback)


# =============================================================================
# Retrieval — query the KB for matching examples
# =============================================================================
def retrieve_examples(
    sb: Any,
    check_id: str | None,
    family: str | None,
    *,
    max_examples: int = 3,
    min_confidence: int = 50,
) -> list[KBExample]:
    """Fetch proven fixes from remediation_kb matching the current finding.

    Strategy:
        1. Exact check_id match (up to max_examples)
        2. If fewer than max_examples found, backfill with same-family matches
        3. Filter by min_confidence to avoid low-quality examples
        4. Rank by confidence_score DESC, then success_rate DESC

    Args:
        sb:             Supabase client (public schema)
        check_id:       Scanner check identifier (e.g. "CKV_AWS_18")
        family:         Remediation family (e.g. "public_exposure")
        max_examples:   Maximum number of examples to return
        min_confidence: Minimum confidence_score to include

    Returns:
        List of KBExample (may be empty if no matches)
    """
    examples: list[KBExample] = []
    seen_ids: set[int] = set()

    # --- Pass 1: exact check_id match ---
    if check_id:
        try:
            resp = (
                sb.table("remediation_kb")
                .select("*")
                .eq("check_id", check_id)
                .eq("is_active", True)
                .gte("confidence_score", min_confidence)
                .order("confidence_score", desc=True)
                .order("success_rate", desc=True)
                .limit(max_examples)
                .execute()
            )
            for row in resp.data or []:
                ex = _row_to_example(row, match_type="exact")
                if ex:
                    examples.append(ex)
                    seen_ids.add(ex.kb_id)
        except Exception:  # noqa: BLE001, S110
            pass  # Best-effort — don't block planner

    # --- Pass 2: same-family backfill (if not enough exact matches) ---
    remaining = max_examples - len(examples)
    if remaining > 0 and family:
        try:
            resp = (
                sb.table("remediation_kb")
                .select("*")
                .eq("family", family)
                .eq("is_active", True)
                .gte("confidence_score", min_confidence)
                .order("confidence_score", desc=True)
                .order("success_rate", desc=True)
                .limit(remaining + 5)  # fetch extra to filter out dupes
                .execute()
            )
            for row in resp.data or []:
                if row["id"] in seen_ids:
                    continue
                ex = _row_to_example(row, match_type="family")
                if ex:
                    examples.append(ex)
                    seen_ids.add(ex.kb_id)
                    if len(examples) >= max_examples:
                        break
        except Exception:  # noqa: BLE001, S110
            pass

    # --- Increment reuse counters for returned examples ---
    for ex in examples:
        try:
            increment_reuse_count(sb, ex.kb_id)
        except Exception:  # noqa: BLE001, S110
            pass

    return examples


# =============================================================================
# Format examples for LLM prompt injection
# =============================================================================
def format_examples_for_prompt(examples: list[KBExample]) -> str:
    """Convert KBExample list into a structured string for LLM context.

    Format designed to be:
        - Clear and parseable by the LLM
        - Compact (respects token budget)
        - Action-oriented (shows what worked, not just what was planned)

    Returns empty string if no examples (caller can skip injection).
    """
    if not examples:
        return ""

    sections: list[str] = []
    sections.append(
        "=== PROVEN FIXES FROM KNOWLEDGE BASE ===\n"
        "The following fixes have been VERIFIED SUCCESSFUL in past runs. "
        "Use them as reference when generating your remediation plan. "
        "Adapt the specific values (bucket names, resource addresses) to "
        "match the CURRENT finding, but follow the same structural approach.\n"
    )

    for i, ex in enumerate(examples, 1):
        match_label = "EXACT MATCH" if ex.match_type == "exact" else "SIMILAR (same family)"
        header = (
            f"--- Example {i} [{match_label}] ---\n"
            f"Check: {ex.check_id} | Family: {ex.family} | "
            f"Confidence: {ex.confidence_score}/100 | "
            f"Success Rate: {ex.success_rate:.0f}%"
        )
        sections.append(header)

        if ex.finding_summary:
            sections.append(f"Finding: {ex.finding_summary}")
        if ex.root_cause:
            sections.append(f"Root Cause: {ex.root_cause}")
        if ex.resource_type:
            sections.append(f"Resource: {ex.resource_type}")

        # Format remediation steps
        if ex.remediation_steps:
            sections.append("\nProven Remediation Steps:")
            for j, step in enumerate(ex.remediation_steps, 1):
                step_text = step.get("step") or step.get("action") or ""
                source_url = step.get("source_url") or ""
                step_line = f"  {j}. {step_text}"
                if source_url:
                    step_line += f"\n     Source: {source_url}"
                sections.append(step_line)

        # Format rollback (condensed)
        if ex.rollback_steps:
            sections.append(f"\nProven Rollback ({len(ex.rollback_steps)} steps):")
            for j, step in enumerate(ex.rollback_steps, 1):
                step_text = step.get("step") or step.get("action") or ""
                sections.append(f"  {j}. {step_text}")

        # Validation summary (what proved it worked)
        if ex.validation_results:
            passed = sum(1 for v in ex.validation_results if v.get("passed"))
            total = len(ex.validation_results)
            sections.append(f"\nValidation: {passed}/{total} checks passed")

        sections.append("")  # blank line between examples

    sections.append("=== END KNOWLEDGE BASE EXAMPLES ===\n")

    return "\n".join(sections)


# =============================================================================
# Format for agentic path (more concise, tool-oriented)
# =============================================================================
def format_examples_for_agentic_prompt(examples: list[KBExample]) -> str:
    """Shorter format for the agentic path — the agent does its own research,
    so we just provide the structural pattern, not full prose.

    Returns empty string if no examples.
    """
    if not examples:
        return ""

    lines: list[str] = [
        "\n[KNOWLEDGE BASE — PROVEN FIX PATTERNS]\n"
        "These patterns WORKED in verified past runs. Follow the same "
        "structural approach but adapt values to the current finding:\n"
    ]

    for i, ex in enumerate(examples, 1):
        lines.append(f"Pattern {i} (check={ex.check_id}, confidence={ex.confidence_score}):")

        if ex.remediation_steps:
            commands = []
            for step in ex.remediation_steps:
                step_text = step.get("step") or step.get("action") or ""
                # Extract just the command portion if present
                if "Command:" in step_text:
                    cmd_part = step_text.split("Command:", 1)[1].strip()
                    cmd_line = cmd_part.split("\n")[0].strip()
                    if cmd_line:
                        commands.append(cmd_line)
                elif step_text:
                    commands.append(step_text[:150])

            if commands:
                lines.append("  Steps: " + " → ".join(commands[:5]))

        if ex.rollback_steps:
            lines.append(f"  Rollback: {len(ex.rollback_steps)} steps available")

        lines.append("")

    lines.append("[END KNOWLEDGE BASE]\n")
    return "\n".join(lines)


# =============================================================================
# Internal helpers
# =============================================================================
def _row_to_example(row: dict, match_type: str = "exact") -> KBExample | None:
    """Convert a DB row dict into a KBExample dataclass."""
    try:
        # Parse JSONB fields
        remediation_steps = row.get("remediation_steps") or []
        if isinstance(remediation_steps, str):
            remediation_steps = json.loads(remediation_steps)

        rollback_steps = row.get("rollback_steps") or []
        if isinstance(rollback_steps, str):
            rollback_steps = json.loads(rollback_steps)

        validation_results = row.get("validation_results") or []
        if isinstance(validation_results, str):
            validation_results = json.loads(validation_results)

        return KBExample(
            kb_id=row["id"],
            check_id=row.get("check_id") or "",
            family=row.get("family") or "",
            finding_summary=row.get("finding_summary") or "",
            root_cause=row.get("root_cause") or "",
            remediation_steps=remediation_steps,
            rollback_steps=rollback_steps,
            validation_results=validation_results,
            resource_type=row.get("resource_type"),
            scanner_type=row.get("scanner_type"),
            file_path=row.get("file_path"),
            confidence_score=row.get("confidence_score") or 0,
            success_rate=float(row.get("success_rate") or 0),
            times_reused=row.get("times_reused") or 0,
            match_type=match_type,
        )
    except Exception:
        return None
