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

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

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

OUTPUT SCHEMA (all four top-level keys REQUIRED — `pathways` array MUST be
present with at least one entry, or the output will be rejected):
{
  "finding": "<1-2 sentences, 20-400 chars>",
  "root_cause": "<1-2 sentences, 20-400 chars>",
  "impact": "<1-2 sentences, 20-400 chars>",
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

CRITICAL: emit ALL four top-level keys. Do NOT emit only finding/root_cause/impact
without the pathways array — the pathways array is what carries the actual
adapted steps and is what the parser reads. Emit ONLY the JSON. No prose.
"""


def _build_adaptation_messages(
    recipe_row: dict,
    issue: dict,
    family: str,
    iac_context: dict,
    target_file_content: str | None = None,
    target_file_truncated: bool = False,
) -> list:
    """Build the LLM messages for the adaptation call.

    When `target_file_content` is provided, it's injected as a GROUND TRUTH
    message BEFORE the recipe payload. The LLM composes old_text against the
    NEW file's real content instead of blindly copying literals from the KB
    recipe's source file. This eliminates the cross-file phantom-success
    class of bug (KB recipe from config.py applied blind to auth.py).
    """
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

    messages = [SystemMessage(content=_ADAPTATION_SYSTEM_PROMPT)]
    if target_file_content:
        target_file = iac_context.get("file_path") or "<unknown>"
        trunc_note = " (TRUNCATED)" if target_file_truncated else ""
        messages.append(
            HumanMessage(
                content=(
                    f"# GROUND TRUTH — actual current content of {target_file}{trunc_note}\n"
                    f"# The proven_recipe below was captured from a DIFFERENT file. Its\n"
                    f"# `remediation_steps` contain literal old_text values from THAT file.\n"
                    f"# When you emit adapted steps, compose old_text from the actual\n"
                    f"# bytes below — DO NOT copy the recipe's literals verbatim if this\n"
                    f"# file uses different variable names / strings / positions.\n\n"
                    f"{target_file_content}"
                )
            )
        )
    messages.append(HumanMessage(content=user_content))
    return messages


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

    # 3. Pre-fetch the target file content so the adaptation LLM can compose
    #    old_text against real bytes (Fix A). Prevents cross-file phantom
    #    successes where a KB recipe's literals from file X get blindly
    #    reused on file Y that doesn't contain them. Best-effort — if fetch
    #    fails, adaptation still runs blind (falls back to prior behavior).
    target_content: str | None = None
    target_truncated = False
    target_path = iac_context.get("file_path")
    if target_path and isinstance(target_path, str) and target_path.startswith("/"):
        try:
            from .tools.file_fetch import fetch_file  # noqa: PLC0415
            from .tools.budget import AgentBudget  # noqa: PLC0415

            # Small budget just for this one fetch — we're not doing web research
            _kb_budget = AgentBudget(max_calls=2, max_cost_usd=0.10)
            _prefetch = fetch_file(
                target_path,
                _kb_budget,
                target_instance_id=None,  # falls back to settings.fixer_env2_instance_id
                run_id=run_id,
                emit_fn=emit_fn,
            )
            if _prefetch.get("exists") and _prefetch.get("content"):
                target_content = _prefetch["content"]
                target_truncated = bool(_prefetch.get("truncated"))
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"📎 KB adapter pre-fetched {_prefetch['content_length']} chars of "
                    f"{target_path} — recipe will be adapted to actual file bytes",
                )
        except Exception as _e:  # noqa: BLE001
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"⚠ KB adapter file_fetch skipped ({type(_e).__name__}: {str(_e)[:100]}) "
                f"— falling back to blind adaptation",
            )

    # 4. Build adaptation messages and call LLM
    try:
        messages = _build_adaptation_messages(
            candidate,
            issue,
            family,
            iac_context,
            target_file_content=target_content,
            target_file_truncated=target_truncated,
        )

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
        # Try direct parse first, then extract JSON from fences.
        # capture_error collects the pydantic ValidationError so we can feed
        # the EXACT missing/wrong field back to the LLM on retry.
        first_errors: list = []
        output = _parse_adaptation_output(text, capture_error=first_errors)

        if output is None:
            # ONE retry with the parse error fed back. Costs 1 extra LLM call
            # (~$0.02, ~5s) vs falling through to full agentic path (~5-15 calls,
            # ~60-90s, ~$0.10). We now pass the EXACT pydantic validation error
            # to the LLM so it knows precisely which field is missing/wrong,
            # rather than a generic "shape wrong" hint that it may not act on.
            first_err = first_errors[0] if first_errors else "unknown parse error"
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"📚 KB replay: first adaptation attempt failed to parse — "
                f"validation error: {first_err[:220]}. Retrying with feedback...",
            )
            retry_messages = messages + [
                AIMessage(content=text),
                HumanMessage(
                    content=(
                        "Your previous response failed strict schema validation with this "
                        f"EXACT pydantic error:\n\n{first_err}\n\n"
                        "Fix ONLY the specific field(s) named in the error above. Preserve "
                        "every other value you already emitted. The schema requires: "
                        "top-level `finding`/`root_cause`/`impact` (each 20-400 chars) plus "
                        "`pathways` (array of 1-3 entries). Each pathway needs objective, "
                        "security_coverage, remediation_steps, rollback_plan (with supported, "
                        "objective, steps, validation, explanation), validation_tests, "
                        "test_scripts, execution_strategy, advantages, considerations. "
                        "Emit ONLY the corrected JSON, no prose."
                    )
                ),
            ]
            retry_errors: list = []
            try:
                retry_response = llm.invoke(retry_messages)
                retry_text = (
                    retry_response.content
                    if isinstance(retry_response.content, str)
                    else json.dumps(retry_response.content)
                )
                output = _parse_adaptation_output(retry_text, capture_error=retry_errors)
            except Exception as retry_err:  # noqa: BLE001
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"📚 KB replay: retry LLM call raised "
                    f"({type(retry_err).__name__}: {str(retry_err)[:100]})",
                )
                output = None

            if output is None:
                retry_err_msg = retry_errors[0] if retry_errors else "no retry error captured"
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "ERROR",
                    f"📚 KB replay: adaptation output unparseable after 1 retry — "
                    f"retry validation error: {retry_err_msg[:220]}. Falling through to agentic.",
                )
                return None, None
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                "📚 KB replay: retry succeeded — proceeding with adapted recipe.",
            )

        # 4. Ensure validation_tests include the re-scan from the KB entry.
        # The adaptation LLM sometimes drops or truncates validation_tests.
        # The KB entry's validation_results contain the proven tests (including
        # the mandatory re-scan). Inject any missing re-scan test directly
        # from the KB rather than trusting the LLM to reproduce it.
        output = _ensure_rescan_in_validation(output, candidate)

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
# Ensure re-scan is present in validation_tests
# =============================================================================
# Scanner CLI verbs used to detect re-scan tests (same list as iac_strategy.py)
_SCANNER_CLI_VERBS = (
    "checkov",
    "trivy",
    "semgrep",
    "bandit",
    "tfsec",
    "kics",
    "terrascan",
    "snyk",
    "grype",
    "sonar-scanner",
)


def _ensure_rescan_in_validation(
    output: LLMRemediationOutput,
    kb_row: dict,
) -> LLMRemediationOutput:
    """Inject the KB entry's re-scan test into the output's validation_tests
    if the LLM dropped it during adaptation.

    The KB entry's `validation_results` contains the proven tests from the
    original successful run — including the mandatory scanner re-scan. The
    adaptation LLM sometimes drops or truncates validation_tests. This
    function checks each pathway: if no validation_test looks like a scanner
    re-scan, inject the one from the KB entry.

    Mutates the output in place and returns it.
    """
    # Parse KB validation_results
    kb_validations = kb_row.get("validation_results") or []
    if isinstance(kb_validations, str):
        kb_validations = json.loads(kb_validations)

    # Find the re-scan test in KB validations
    kb_rescan = None
    for v in kb_validations:
        cmd = (v.get("command") or "").strip()
        if not cmd:
            continue
        first_token = cmd.split(maxsplit=1)[0].rsplit("/", 1)[-1]
        if first_token in _SCANNER_CLI_VERBS:
            kb_rescan = v
            break

    if kb_rescan is None:
        # KB entry itself has no re-scan — nothing to inject
        return output

    # Check each pathway's validation_tests for a re-scan
    for pathway in output.pathways:
        has_rescan = False
        for test in pathway.validation_tests:
            cmd = (test.command or "").strip()
            if not cmd:
                continue
            first_token = cmd.split(maxsplit=1)[0].rsplit("/", 1)[-1]
            if first_token in _SCANNER_CLI_VERBS:
                has_rescan = True
                break

        if not has_rescan:
            # Inject the KB's re-scan as an additional validation_test
            from ...models import ValidationTest  # noqa: PLC0415

            rescan_test = ValidationTest(
                name=kb_rescan.get("test_name")
                or kb_rescan.get("name")
                or "Re-scan with original scanner",
                method="cli",
                command=kb_rescan.get("command") or "",
                expected=kb_rescan.get("expected") or '"failed_checks": []',
                source=kb_rescan.get("source") or "Knowledge Base",
            )
            pathway.validation_tests.append(rescan_test)

    return output


# =============================================================================
# Parse adaptation LLM output
# =============================================================================
def _parse_adaptation_output(
    text: str, capture_error: list | None = None
) -> LLMRemediationOutput | None:
    """Parse the adaptation LLM's output as LLMRemediationOutput.

    Handles:
        - Bare JSON
        - JSON inside ```json ... ``` fences
        - JSON with leading/trailing prose

    If `capture_error` is a list, the last pydantic ValidationError message is
    appended to it so callers can surface the exact reason parsing failed
    (missing required field, wrong type, etc.). Only errors from the FINAL
    parse attempt survive — earlier attempt errors are overwritten.
    """
    import re  # noqa: PLC0415

    if not text or not text.strip():
        if capture_error is not None:
            capture_error.append("empty or whitespace-only response")
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

    last_err = None
    for candidate in candidates:
        try:
            return LLMRemediationOutput.model_validate_json(candidate)
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue

    if capture_error is not None and last_err is not None:
        # Compact the pydantic error to a single line — usually the first 2-3
        # error entries are the most informative (missing required field name,
        # wrong type at path). Full traces are enormous.
        err_str = str(last_err).replace("\n", " ")[:400]
        capture_error.append(err_str)
    return None
