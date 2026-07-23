"""Knowledge Base Direct Replay — skip the agentic path for proven fixes.

When the remediation_kb has a verified successful recipe for the current
finding's (check_id, resource_type), this module adapts the proven steps
to the current finding's specific values (file paths, resource names) via
a single constrained LLM call — no web search, no tool calls, no variance.

Flow:
    1. Query KB for exact match (check_id + resource_type + confidence >= 70)
    2. If found → single LLM call to adapt values → return LLMRemediationOutput
    3. If not found or adaptation fails → return None (caller falls through
       to agentic/hybrid path)

Design principles:
    - FAIL-OPEN: any error returns None, caller continues with normal path
    - SINGLE LLM CALL: no tools, no retry loop — just value substitution
    - TRUST THE RECIPE: output uses the recipe's structure without re-verification
    - TRACE EVERYTHING: emit clear messages so operators know which path ran

Public API:
    try_kb_replay(issue, family, raw, sb, run_id, emit_fn) -> LLMRemediationOutput | None
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ...models import LLMRemediationOutput
from ..llm import get_chat_llm


# =============================================================================
# KB retrieval for direct replay (stricter than the few-shot retrieval)
# =============================================================================
def _find_replay_candidate(
    sb: Any,
    check_id: str,
    resource_type: str | None,
) -> dict | None:
    """Query remediation_kb for a direct-replay candidate.

    Criteria (all must be true):
        - check_id matches exactly
        - resource_type matches exactly (if provided)
        - confidence_score >= 70
        - is_active = True

    Returns the top-1 row (ranked by confidence DESC, success_rate DESC,
    created_at DESC), or None if no match.
    """
    if not check_id:
        return None

    query = (
        sb.table("remediation_kb")
        .select("*")
        .eq("check_id", check_id)
        .eq("is_active", True)
        .gte("confidence_score", 70)
        .order("confidence_score", desc=True)
        .order("success_rate", desc=True)
        .order("created_at", desc=True)
        .limit(1)
    )

    # Add resource_type filter if available
    if resource_type:
        query = query.eq("resource_type", resource_type)

    resp = query.execute()
    rows = resp.data or []
    return rows[0] if rows else None


# =============================================================================
# LLM adaptation prompt — constrained substitution only
# =============================================================================
_ADAPTATION_SYSTEM_PROMPT = """\
You are a remediation step adapter. You receive a PROVEN remediation recipe
(steps that successfully fixed a vulnerability in a past run) and a NEW
finding with its specific context values.

Your ONLY job: emit the same steps with values adapted to the new finding.

RULES:
1. DO NOT change the structure, approach, number of steps, or sequence.
2. DO NOT add new steps or remove existing ones.
3. DO NOT change the Command: approach (if it uses cat >> heredoc, keep it;
   if it uses sed, keep it).
4. ONLY replace these values where they differ between recipe and new finding:
   - file_path / working_directory
   - bucket names (if the finding references a different bucket)
   - resource addresses (aws_s3_bucket.X, aws_security_group.Y)
   - security group names
   - check IDs in re-scan commands
5. Keep all source/source_url fields from the recipe unchanged.
6. Emit valid JSON matching the OUTPUT SCHEMA exactly.

OUTPUT SCHEMA:
{
  "finding": "<1-2 sentences>",
  "root_cause": "<1-2 sentences>",
  "impact": "<1-2 sentences>",
  "pathways": [{
    "objective": "<1 sentence>",
    "security_coverage": "complete",
    "remediation_steps": [{"step": "...", "source": "...", "source_url": "..."}],
    "rollback_plan": {"supported": true, "objective": "...", "preconditions": [],
                      "steps": [...], "validation": [...], "limitations": [],
                      "explanation": "...", "recommended_recovery": null},
    "validation_tests": [{"name": "...", "method": "cli", "command": "...",
                          "expected": "...", "source": "..."}],
    "test_scripts": [{"language": "bash", "description": "...", "code": "..."}],
    "execution_strategy": "<2-3 sentences>",
    "advantages": [...],
    "considerations": [...]
  }]
}

Emit ONLY the JSON. No prose, no explanation.
"""


def _build_adaptation_messages(
    recipe_row: dict,
    issue: dict,
    family: str,
    iac_context: dict,
) -> list:
    """Build the LLM messages for the adaptation call."""
    # Parse recipe steps
    recipe_steps = recipe_row.get("remediation_steps") or []
    if isinstance(recipe_steps, str):
        recipe_steps = json.loads(recipe_steps)

    rollback_steps = recipe_row.get("rollback_steps") or []
    if isinstance(rollback_steps, str):
        rollback_steps = json.loads(rollback_steps)

    validation_results = recipe_row.get("validation_results") or []
    if isinstance(validation_results, str):
        validation_results = json.loads(validation_results)

    # Build the user message with recipe + new finding context
    user_content = json.dumps(
        {
            "proven_recipe": {
                "check_id": recipe_row.get("check_id"),
                "family": recipe_row.get("family"),
                "finding_summary": recipe_row.get("finding_summary"),
                "root_cause": recipe_row.get("root_cause"),
                "resource_type": recipe_row.get("resource_type"),
                "file_path": recipe_row.get("file_path"),
                "remediation_steps": recipe_steps,
                "rollback_steps": rollback_steps,
            },
            "new_finding": {
                "id": issue.get("id"),
                "check_id": issue.get("source_vuln_id") or issue.get("cve_id"),
                "title": issue.get("title"),
                "severity": issue.get("severity"),
                "file_path": iac_context.get("file_path"),
                "working_directory": iac_context.get("working_directory"),
                "resource_name": iac_context.get("resource_name"),
                "scanner_type": iac_context.get("scanner_type"),
                "family": family,
            },
        },
        indent=2,
        default=str,
    )

    return [
        SystemMessage(content=_ADAPTATION_SYSTEM_PROMPT),
        HumanMessage(content=user_content),
    ]


# =============================================================================
# Public API
# =============================================================================
def try_kb_replay(
    issue: dict,
    family: str,
    raw: dict | None,
    *,
    sb: Any,
    run_id: str,
    emit_fn,
) -> tuple[LLMRemediationOutput | None, int | None]:
    """Attempt to produce a remediation package from KB replay.

    Args:
        issue:   the full issues row
        family:  pre-classified family
        raw:     raw_finding dict (for IaC context extraction)
        sb:      supabase client
        run_id:  for trace correlation
        emit_fn: trace emitter

    Returns:
        (LLMRemediationOutput, kb_id) on success — caller can skip agentic path.
        (None, None) if no candidate found or adaptation failed — caller
        should fall through to the agentic/hybrid path.
    """
    from .planner import _extract_iac_context  # noqa: PLC0415

    # 1. Extract context needed for KB lookup
    iac_context = _extract_iac_context(issue, raw)
    check_id = issue.get("source_vuln_id") or issue.get("cve_id")
    resource_type = iac_context.get("resource_name")

    if not check_id:
        return None, None

    # 2. Query KB for a replay candidate
    try:
        candidate = _find_replay_candidate(sb, check_id, resource_type)
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"📚 KB replay lookup failed: {type(e).__name__}: {str(e)[:200]} — "
            "falling through to agentic path.",
        )
        return None, None

    if candidate is None:
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"📚 KB replay: no candidate found for check_id={check_id}, "
            f"resource_type={resource_type} — using agentic path.",
        )
        return None, None

    kb_id = candidate["id"]
    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"📚 KB replay: found candidate KB #{kb_id} (check={check_id}, "
        f"confidence={candidate.get('confidence_score')}, "
        f"reused={candidate.get('times_reused')} times). "
        f"Adapting proven recipe via constrained LLM call...",
    )

    # 3. Build adaptation messages and call LLM
    try:
        messages = _build_adaptation_messages(candidate, issue, family, iac_context)

        llm = get_chat_llm(
            run_id=run_id,
            agent="sub-agent-3",
            model="gpt-4o",
            temperature=0.1,
            max_tokens=4000,
            emit_fn=emit_fn,
        )

        response = llm.invoke(messages)
        text = (
            response.content if isinstance(response.content, str) else json.dumps(response.content)
        )

        # Parse the response as LLMRemediationOutput
        # Try direct parse first, then extract JSON from fences
        output = _parse_adaptation_output(text)

        if output is None:
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"📚 KB replay: adaptation LLM returned unparseable output "
                f"(first 200 chars: {text[:200]!r}) — falling through to agentic path.",
            )
            return None, None

        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"📚 KB replay SUCCESS — adapted recipe KB #{kb_id} for "
            f"issue #{issue.get('id')} ({check_id}). "
            f"Skipping agentic/hybrid path.",
        )
        return output, kb_id

    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"📚 KB replay: adaptation failed: {type(e).__name__}: {str(e)[:200]} "
            f"— falling through to agentic path.",
        )
        return None, None


# =============================================================================
# Parse adaptation LLM output
# =============================================================================
def _parse_adaptation_output(text: str) -> LLMRemediationOutput | None:
    """Parse the adaptation LLM's output as LLMRemediationOutput.

    Handles:
        - Bare JSON
        - JSON inside ```json ... ``` fences
        - JSON with leading/trailing prose
    """
    import re  # noqa: PLC0415

    if not text or not text.strip():
        return None

    # Try bare parse
    candidates = []
    stripped = text.strip()
    candidates.append(stripped)

    # Try fenced code blocks
    for m in re.finditer(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL):
        candidates.append(m.group(1).strip())

    # Try first balanced { ... } block
    start = text.find("{")
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : i + 1])
                    break

    for candidate in candidates:
        try:
            return LLMRemediationOutput.model_validate_json(candidate)
        except Exception:  # noqa: BLE001, S112
            continue

    return None
