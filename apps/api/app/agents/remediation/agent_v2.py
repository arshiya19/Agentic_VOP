"""Sub-Agent 3 v2.0 — Agentic Remediation Researcher.

Given ONE finding, this agent:
  1. Loads prompt v2.0 from prompt_db (ReAct instructions + output schema)
  2. Binds `web_search` + `url_fetch` as tools the LLM can call
  3. Iterates: LLM reasons → calls a tool → observes → repeats
  4. When LLM stops calling tools, tries to parse its final message as JSON
  5. If parse fails, does a structured-output synthesis pass as backup
  6. Returns LLMRemediationOutput (Pydantic-validated) OR None

None means the caller should fall back to the hybrid pattern-based planner.
Failure modes that return None:
  - Budget cap reached (call count OR $ cap)
  - LLM couldn't produce valid JSON after synthesis retry
  - Any unhandled tool error
  - Max iterations exhausted without a final answer

Public API:
  run_agentic_planner(issue, asset, family, run_id, emit_fn, ...) -> LLMRemediationOutput | None
"""

from __future__ import annotations

import json
import re
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.tools import tool as langchain_tool

from ...models import LLMRemediationOutput
from ..llm import get_chat_llm
from .tools.budget import AgentBudget
from .tools.url_fetch import fetch_url
from .tools.web_search import web_search
from .verifier import (
    _MIN_STEPS_BY_FAMILY,
    VerificationReport,
    _extract_commands,
    scan_placeholder_flags,
    verify_output,
)


# Return type: (output, verification_report). None means agent failed → fallback.
AgentResult = tuple[LLMRemediationOutput, VerificationReport] | None


# =============================================================================
# Enterprise floor — the agent CANNOT synthesize until it has done at least
# this many url_fetch calls against distinct authoritative sources for the
# given family. Prevents "2-step packages after 2 fetches" pathological cases.
# Kept in sync with the per-family depth minimums in verifier.py.
# =============================================================================
_MIN_FETCHES_BY_FAMILY = {
    "public_exposure": 3,
    "network_exposure": 3,
    "injection": 3,
    "vulnerable_dependency": 4,
    "os_vulnerability": 3,
}

# How many total tool calls we reserve for the depth-retry + verifier pass.
# When budget drops below this, we let the LLM synthesize with what it has
# rather than forcing more research it doesn't have budget for.
_RESERVE_CALLS_FOR_VERIFICATION = 5


# =============================================================================
# Prompt loading
# =============================================================================
def _load_prompt_v2(sb_pub) -> dict:
    """Load the v2.0 (AGENTIC) sub-agent-3 prompt. Both v1.4 (hybrid) and
    v2.0 (agent) are active in prompt_db — select by version explicitly."""
    resp = (
        sb_pub.table("prompt_db")
        .select("agent,version,model,prompt_text,parameters")
        .eq("agent", "sub-agent-3")
        .eq("version", "v2.0")
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        raise RuntimeError(
            "No sub-agent-3 v2.0 prompt row in prompt_db. "
            "Apply migration 0048_sub_agent_3_prompt_v2.sql."
        )
    return rows[0]


# =============================================================================
# Tool wrappers — closure captures per-run state (budget, run_id, emit_fn)
# =============================================================================
def _make_tools(
    budget: AgentBudget,
    run_id: str,
    emit_fn,
) -> list:
    """Wrap web_search + fetch_url as LangChain tools with per-run state
    baked in. LLM sees clean signatures (just the query/url arg).
    """

    @langchain_tool
    def web_search_tool(query: str) -> str:
        """Search the web for authoritative remediation guidance.

        Use this to find fix instructions for a specific CVE, IaC check ID
        (e.g. CKV_AWS_20), CWE (e.g. CWE-89), or resource + best-practice
        query. Returns up to 6 results, ranked by authority tier (Tier 1 =
        AWS/CIS/NVD/CISA docs, Tier 4 = blogs).

        Args:
            query: the search query — be specific, use identifiers.
        Returns:
            Formatted string listing each result's title, URL, tier, snippet.
        """
        result = web_search(query, budget, run_id=run_id, emit_fn=emit_fn)
        lines = [f"Search: {query}\nReturned {len(result['results'])} results:\n"]
        for i, r in enumerate(result["results"], start=1):
            lines.append(
                f"[{i}] Tier {r['authority_tier']} · {r['title']}\n"
                f"    URL: {r['url']}\n"
                f"    {r['snippet'][:300]}\n"
            )
        return "\n".join(lines)

    @langchain_tool
    def url_fetch_tool(url: str) -> str:
        """Fetch a URL and return its cleaned readable content.

        Use this to read a page found via web_search. Prefer Tier 1-2 URLs.
        Returns extracted markdown text with headings + code blocks preserved.

        Args:
            url: the URL to fetch — must be from a prior web_search result.
        Returns:
            Cleaned page content (up to 8000 chars, then truncated). If the
            page returned little/no extractable text (JS-rendered SPAs etc.),
            the response is prefixed with a WARNING telling you to find a
            different source before synthesizing.
        """
        result = fetch_url(url, budget, run_id=run_id, emit_fn=emit_fn)
        # If extraction was empty/thin, prepend an explicit directive so the
        # LLM cannot silently synthesize from a page that gave it 0 chars.
        warning = result.get("quality_warning")
        header_lines = [
            f"# {result['title']}" if result.get("title") else "",
            f"# URL: {result['final_url']}",
            f"# Chars extracted: {result['content_length']}",
        ]
        if warning:
            header_lines.append(
                f"# ⚠ CONTENT-QUALITY WARNING ({warning['level']}): {warning['directive']}"
            )
        header = "\n".join(line for line in header_lines if line)
        return f"{header}\n\n{result['text']}"

    return [web_search_tool, url_fetch_tool]


# =============================================================================
# JSON extraction — the LLM's final message may or may not be pure JSON
# =============================================================================
def _try_parse_final_answer(
    text: str,
    *,
    run_id: str | None = None,
    emit_fn=None,
    context: str = "parse",
) -> LLMRemediationOutput | None:
    """Parse text as LLMRemediationOutput JSON. Handles common wrappings:
      - Bare JSON
      - JSON inside ```json ... ``` fences
      - JSON with leading/trailing prose (extract first {...} balanced block)
      - Common LLM syntax issues: trailing commas, single quotes, unescaped
        newlines inside string values

    On failure, if emit_fn+run_id supplied, logs a preview of the LLM output
    and the last validation error so the developer can see WHY it failed.
    """
    if not text or not text.strip():
        return None

    last_error = ""
    candidates = _candidate_json_slices(text)

    for candidate in candidates:
        try:
            return LLMRemediationOutput.model_validate_json(candidate)
        except Exception as e:  # noqa: BLE001
            last_error = f"{type(e).__name__}: {str(e)[:250]}"
            # Try a lenient repair for common syntax slips
            repaired = _repair_common_json_errors(candidate)
            if repaired and repaired != candidate:
                try:
                    return LLMRemediationOutput.model_validate_json(repaired)
                except Exception as e2:  # noqa: BLE001
                    last_error = f"repair failed: {type(e2).__name__}: {str(e2)[:200]}"
            continue

    # All candidates failed — emit diagnostic so we can see what the LLM produced
    if emit_fn and run_id:
        preview = text[:400].replace("\n", " ⏎ ").replace("  ", " ")
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"[{context}] JSON parse failed after {len(candidates)} candidate(s). "
            f"Last error: {last_error}. LLM output preview (first 400 chars): {preview}",
        )
    return None


def _repair_common_json_errors(text: str) -> str | None:
    """Character-level JSON hygiene — nothing shape-aware.

    Handles:
      - Trailing commas before `}` or `]`
      - JavaScript-style comments `//` and `/* */`
      - Smart quotes replaced with ASCII

    Structural shape normalization (action/command/why → step, or step →
    command inside a ValidationTest slot) lives in the Pydantic schemas
    themselves as @model_validator(mode='before') — see RemediationStep
    and ValidationTest in app/models.py. Keeping shape logic there means
    it applies wherever the schema is used (top-level or nested) with
    zero location tracking here.

    Returns None when nothing changed (short-circuit for the caller).
    """
    repaired = text
    # Strip line comments — but ONLY when they follow whitespace or a comma
    # (avoid mutilating URLs like "http://...")
    repaired = re.sub(r"(?m)(?<=[\s,\]{}])\s*//[^\n]*", "", repaired)
    # Strip block comments
    repaired = re.sub(r"/\*.*?\*/", "", repaired, flags=re.DOTALL)
    # Trailing commas: `,}` or `,]`
    repaired = re.sub(r",(\s*[}\]])", r"\1", repaired)
    # Smart quotes → ASCII
    repaired = repaired.replace("“", '"').replace("”", '"')
    repaired = repaired.replace("‘", "'").replace("’", "'")

    return repaired if repaired != text else None


def _candidate_json_slices(text: str) -> list[str]:
    """Yield plausible JSON substrings from `text`, cheapest first.

    Order:
      1. Text stripped of leading/trailing whitespace
      2. Content inside ```json ... ``` or ``` ... ``` fences
      3. First balanced { ... } block found (crude but effective)
    """
    slices: list[str] = []
    stripped = text.strip()
    if stripped:
        slices.append(stripped)

    # Fenced code blocks (```json or plain ```)
    for m in re.finditer(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL):
        slices.append(m.group(1).strip())

    # First balanced {...} block — crude bracket counter
    start = text.find("{")
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    slices.append(text[start : i + 1])
                    break
    return slices


# =============================================================================
# Post-parse depth check — force LLM to expand if it under-produced
# =============================================================================
def _distinct_hosts_fetched(messages: list[Any]) -> set[str]:
    """Scan the ToolMessage history for URLs the agent has read this run.
    Used both by the fetch-floor gate (below) and by the expansion prompt
    (so we can remind the LLM which sources it already has).
    """
    from urllib.parse import urlparse  # noqa: PLC0415

    hosts: set[str] = set()
    for m in messages:
        if isinstance(m, ToolMessage):
            content = m.content if isinstance(m.content, str) else ""
            for line in content.splitlines():
                if line.startswith("# URL:") or line.startswith("URL:"):
                    url = line.split(":", 1)[1].strip()
                    try:
                        h = urlparse(url).netloc.lower()
                        if h:
                            hosts.add(h)
                    except Exception:  # noqa: BLE001, S110 — malformed URL, ignore
                        pass
    return hosts


def _count_extractable_commands(parsed: LLMRemediationOutput) -> int:
    """How many CLI/code commands does the extractor find across all steps?

    Used by _maybe_expand_for_depth as a second trigger: if the LLM produced
    prose-only steps (no Command: block, no fenced code, no shell prompts),
    count is 0 and we force an expansion to fix the STEP FORMAT.
    """
    total = 0
    for pathway in parsed.pathways or []:
        for step in (pathway.remediation_steps or []) + (
            list(pathway.rollback_plan.steps) if pathway.rollback_plan else []
        ):
            text = getattr(step, "step", "") or ""
            total += len(_extract_commands(text))
    return total


def _maybe_expand_for_depth(
    parsed: LLMRemediationOutput,
    family: str | None,
    llm,
    messages: list[Any],
    run_id: str,
    emit_fn,
    budget: AgentBudget,
) -> LLMRemediationOutput:
    """Re-invoke LLM ONCE if the draft:
      (a) has any pathway below family minimum step count, OR
      (b) has zero extractable commands (all steps are pure prose)

    Both cases produce an unusable package — under-produced or unrunnable.
    Costs zero tool calls — uses only the message history already gathered.
    """
    if not parsed.pathways:
        return parsed

    reasons: list[str] = []
    shortfalls: list[tuple[int, int]] = []

    # Trigger A — under-produced
    min_steps = _MIN_STEPS_BY_FAMILY.get(family or "") if family else None
    if min_steps:
        for i, p in enumerate(parsed.pathways):
            n = len(p.remediation_steps or [])
            if n < min_steps:
                shortfalls.append((i, n))
        if shortfalls:
            reasons.append(f"pathway step-count shortfalls: {shortfalls} (need ≥{min_steps})")

    # Trigger B — no runnable commands (all steps are prose descriptions)
    total_commands = _count_extractable_commands(parsed)
    if total_commands == 0:
        reasons.append(
            "ZERO extractable commands across all steps — steps appear to be "
            "prose descriptions, missing the required Command: block. "
            "This makes the package UNRUNNABLE for production ops."
        )

    if not reasons:
        return parsed

    fetched_hosts = _distinct_hosts_fetched(messages)
    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"↻ RETRY — {'; '.join(reasons)}. Re-invoking for expansion "
        f"(no tool calls — uses fetched sources: {sorted(fetched_hosts)[:5]}).",
    )

    min_rollback = max(
        2, int((min_steps or len(parsed.pathways[0].remediation_steps or [1])) * 0.5)
    )
    target_steps = min_steps or max(6, len(parsed.pathways[0].remediation_steps or [6]))

    expand_msg_parts: list[str] = [
        "Your draft is INCOMPLETE and cannot ship. Problems detected:",
        *(f"  - {r}" for r in reasons),
        "",
        "Re-emit the FULL JSON (same finding/root_cause/impact) fixing ALL of:",
        f"  - remediation_steps: ≥ {target_steps} entries",
        f"  - rollback_plan.steps: ≥ {min_rollback} entries",
        "  - validation_tests: ≥ 3 entries",
        "  - test_scripts: ≥ 2 entries",
        "",
        "**CRITICAL — every remediation_steps entry AND every rollback.steps entry**",
        "**MUST contain a `Command:` block with paste-ready CLI, not prose.** Shape:",
        "",
        "  <Action — 1-2 sentence description>",
        "",
        "  Command:",
        "      <runnable CLI, code, or Terraform block with concrete values>",
        "",
        "  Why: <rationale grounded in the cited source_url>",
        "",
        "Example of what to emit (S3 lockdown backup):",
        "",
        "  Back up the current bucket policy so the change is reversible.",
        "",
        "  Command:",
        "      aws s3api get-bucket-policy --bucket vulnerable_bucket \\",
        "        --output json > vulnerable_bucket-policy-$(date +%Y%m%d).json",
        "",
        "  Why: The AWS S3 User Guide recommends capturing the pre-change policy",
        "  before running put-public-access-block so rollback is a single apply.",
        "",
        'Do NOT emit steps that are just descriptions (e.g. "Review current',
        'security group rules" without a Command: block).',
        "",
        f"Every source_url MUST be a URL you already fetched in this run "
        f"(hosts you have content for: {sorted(fetched_hosts) or '[none]'}). "
        f"Do NOT invent new URLs. Emit JSON only.",
    ]
    expand_msg = HumanMessage(content="\n".join(expand_msg_parts))

    # NOTE: We invoke the plain LLM here (NOT with_structured_output) because
    # LLMRemediationOutput contains `confidence_components: dict[str, Any]`
    # which OpenAI's strict JSON-schema mode rejects. The main agent loop
    # uses raw JSON parsing for the same reason — mirror that shape here.
    try:
        response = llm.invoke(messages + [expand_msg])
        text = (
            response.content if isinstance(response.content, str) else json.dumps(response.content)
        )
        expanded = _try_parse_final_answer(
            text,
            run_id=run_id,
            emit_fn=emit_fn,
            context="depth-retry",
        )
        if expanded is None:
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                "Retry LLM returned non-parseable content — keeping original draft",
            )
            return parsed
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Retry expansion failed: {type(e).__name__}: {str(e)[:150]} — keeping original draft",
        )
        return parsed

    # Guard: only accept expansion when it actually improved things.
    improved = False
    for i, before in shortfalls:
        if i < len(expanded.pathways):
            after = len(expanded.pathways[i].remediation_steps or [])
            if after > before:
                improved = True
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"✓ RETRY pathway {i}: {before} → {after} steps",
                )
    # Also accept if commands appeared where none existed before
    commands_after = _count_extractable_commands(expanded)
    if total_commands == 0 and commands_after > 0:
        improved = True
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"✓ RETRY — commands extracted: 0 → {commands_after} (steps now have Command: blocks)",
        )
    if not improved:
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            "Retry did not improve step count OR command extractability — keeping original draft",
        )
        return parsed
    return expanded


# =============================================================================
# Generic placeholder retry — resource-agnostic. Takes the verifier's flags
# (which use regex patterns that match any placeholder shape, not domain
# knowledge) and asks the LLM to either add a discovery command or drop
# the offending step. No hardcoded knowledge about KMS / VPC / IAM / any
# specific resource type — the LLM decides what discovery command fits.
# =============================================================================
def _maybe_expand_for_placeholders(
    parsed: LLMRemediationOutput,
    report: VerificationReport,
    llm,
    messages: list[Any],
    run_id: str,
    emit_fn,
) -> tuple[LLMRemediationOutput, VerificationReport]:
    """If the verifier flagged unfilled placeholders, re-invoke ONCE with
    the specific placeholders shown + generic remediation instruction.

    Cost: 0 tool calls (LLM only). After a successful retry, re-scans
    placeholder flags on the new output (regex-only, no web calls) and
    updates the report's placeholder_flags in place so downstream
    confidence scoring reflects the improvement.
    """
    if not report or not report.placeholder_flags:
        return parsed, report

    # Group flags by (step_num, pattern, match) so we don't repeat ourselves
    flag_lines: list[str] = []
    seen: set[tuple] = set()
    for f in report.placeholder_flags:
        key = (f.get("step_num"), f.get("pattern"), f.get("match"))
        if key in seen:
            continue
        seen.add(key)
        flag_lines.append(
            f"  - Step {f.get('step_num')}: placeholder {f.get('match')!r} ({f.get('pattern')})"
        )

    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"↻ RETRY — {len(flag_lines)} unfilled placeholder(s) detected. "
        f"Re-invoking to replace with discovery commands or drop the step "
        f"(no tool calls).",
    )

    fetched_hosts = _distinct_hosts_fetched(messages)
    expand_msg = HumanMessage(
        content="\n".join(
            [
                "Your draft has UNFILLED PLACEHOLDERS in remediation commands. Every",
                "command in the output must be directly runnable by production ops.",
                "Placeholders like `<name>`, `{name}`, `YOUR_*`, `/path/to/...`, and",
                "`example.com` make steps unrunnable. Verifier flagged:",
                "",
                *flag_lines,
                "",
                "For EACH placeholder above, choose ONE fix — no other options:",
                "",
                "  (A) Add a NEW step IMMEDIATELY BEFORE the flagged step that runs",
                "      a discovery command to resolve the value at runtime, then",
                "      reference $(that_command) or the resolved variable in the",
                "      flagged step. Example pattern (adapt to the actual resource):",
                "",
                "          aws <service> describe-<resource> \\",
                "            --filters 'Name=<attr>,Values=<from-finding>' \\",
                "            --query '<Resources[0].Id>' --output text",
                "",
                "  (B) REMOVE the flagged step from remediation_steps if the value",
                "      truly cannot be derived and the step is optional. Prefer (A)",
                "      whenever a discovery command exists in the vendor CLI.",
                "",
                "Do NOT invent hardcoded IDs, ARNs, or account numbers. Do NOT",
                "leave the placeholder in place. Do NOT rename the placeholder to a",
                "different placeholder shape.",
                "",
                "Re-emit the FULL JSON (same finding/root_cause/impact + all other",
                "pathway fields) with placeholders replaced or steps removed. Every",
                f"source_url MUST be from the fetched hosts: {sorted(fetched_hosts) or '[none]'}.",
                "Emit JSON only.",
            ]
        )
    )

    try:
        response = llm.invoke(messages + [expand_msg])
        text = (
            response.content if isinstance(response.content, str) else json.dumps(response.content)
        )
        expanded = _try_parse_final_answer(
            text,
            run_id=run_id,
            emit_fn=emit_fn,
            context="placeholder-retry",
        )
        if expanded is None:
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                "Placeholder retry: non-parseable content — keeping original draft",
            )
            return parsed, report
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Placeholder retry failed: {type(e).__name__}: {str(e)[:150]} — "
            "keeping original draft",
        )
        return parsed, report

    # Re-scan the new output for placeholders (regex only, no web calls).
    # Only accept the retry if it strictly reduced the placeholder count.
    new_flags = scan_placeholder_flags(expanded)
    before = len(report.placeholder_flags)
    after = len(new_flags)
    if after < before:
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"✓ PLACEHOLDER RETRY: {before} → {after} unfilled placeholder(s)",
        )
        # Update the report so downstream confidence reflects the improvement.
        # We can't easily remove considerations already stitched in, but the
        # placeholder_flags list is what confidence_agentic reads.
        report.placeholder_flags = new_flags
        return expanded, report

    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"Placeholder retry did not reduce placeholder count ({before} → {after}) — "
        "keeping original draft",
    )
    return parsed, report


# =============================================================================
# Fetch-floor gate — refuse LLM's premature "I'm done" if we haven't done
# enough research for the family. Injects a HumanMessage nudge and loops.
# =============================================================================
def _fetch_floor_ok(family: str | None, budget: AgentBudget) -> tuple[bool, int, int]:
    """Return (allowed_to_finish, fetches_done, fetches_required)."""
    required = _MIN_FETCHES_BY_FAMILY.get(family or "", 2) if family else 2
    done = budget.by_tool.get("url_fetch", 0)
    return (done >= required, done, required)


# =============================================================================
# Main entry point
# =============================================================================
def run_agentic_planner(
    issue: dict,
    asset: dict,
    family: str,
    *,
    run_id: str,
    sb_pub,
    emit_fn,
) -> AgentResult:
    """Run the agentic Sub-Agent 3 for one finding.

    Args:
        issue: full canonical issue row
        asset: resolved asset context (or {} if unattributed)
        family: pre-classified family (public_exposure / injection / ...)
        run_id: agent_run_id for trace correlation
        sb_pub: supabase client for reading prompt_db (public schema)
        emit_fn: trace emitter (emit_trace for real, emit_trace_demo for demo)

    Returns:
        LLMRemediationOutput on success. None when agent fails and caller
        should fall back to hybrid pattern-based planner.
    """
    try:
        prompt_row = _load_prompt_v2(sb_pub)
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Failed to load agent prompt v2: {type(e).__name__}: {str(e)[:200]}",
        )
        return None

    params = prompt_row.get("parameters") or {}
    max_iterations = int(params.get("agent_max_iterations", 12))
    temperature = float(params.get("temperature", 0.2))
    max_tokens = int(params.get("max_tokens", 6000))
    model = prompt_row["model"]

    budget = AgentBudget()
    tools = _make_tools(budget, run_id, emit_fn)

    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"🤖 Agentic remediation starting — family={family}, budget={budget.max_calls} calls / "
        f"${budget.max_cost_usd:.2f} — model={model} @ temp={temperature}",
    )

    # Build the initial context: issue + asset + family passed as JSON
    user_payload = {
        "issue": issue,
        "asset": asset,
        "family": family,
    }

    # --- Knowledge Base injection (few-shot from proven fixes) ---
    kb_context_msg: list[Any] = []
    try:
        from .kb_retrieval import retrieve_examples, format_examples_for_agentic_prompt  # noqa: PLC0415
        from ...db import supabase_admin  # noqa: PLC0415

        sb_pub = supabase_admin()
        check_id = (issue.get("source_vuln_id") or issue.get("cve_id")
                    or (issue.get("source_raw") or {}).get("check_id"))
        kb_examples = retrieve_examples(sb_pub, check_id=check_id, family=family)
        if kb_examples:
            kb_text = format_examples_for_agentic_prompt(kb_examples)
            if kb_text:
                kb_context_msg = [HumanMessage(content=kb_text)]
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"Injected {len(kb_examples)} proven fix pattern(s) from knowledge base",
                )
    except Exception:  # noqa: BLE001, S110
        pass  # KB retrieval is best-effort

    messages: list[Any] = [
        SystemMessage(content=prompt_row["prompt_text"]),
        *kb_context_msg,
        HumanMessage(content=json.dumps(user_payload, default=str)),
    ]

    llm = get_chat_llm(
        run_id=run_id,
        agent="sub-agent-3",
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        emit_fn=emit_fn,
    )
    llm_with_tools = llm.bind_tools(tools)

    # =========================================================================
    # The agent loop: LLM → maybe tool calls → observations → repeat
    # =========================================================================
    # `family` captured for the verifier below (both direct + synth paths need it)
    _family_for_verify = family

    for iteration in range(max_iterations):
        try:
            response: AIMessage = llm_with_tools.invoke(messages)  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"LLM call failed at iteration {iteration + 1}: {type(e).__name__}: {str(e)[:200]}",
            )
            return None

        messages.append(response)

        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            # Model didn't request tools — wants to finish. Gate on fetch floor.
            floor_ok, done, required = _fetch_floor_ok(family, budget)
            budget_remaining = budget.max_calls - budget.call_count
            can_afford_more = budget_remaining > _RESERVE_CALLS_FOR_VERIFICATION

            if not floor_ok and can_afford_more and iteration < max_iterations - 2:
                # PUSH BACK — research floor not met. Force more fetching.
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"▶ FETCH FLOOR ({done}/{required}) — {family} requires more "
                    f"authoritative research before synthesis. Pushing back.",
                )
                messages.append(
                    HumanMessage(
                        content=(
                            f"You've only called url_fetch {done} time(s). Family "
                            f"'{family}' requires content from AT LEAST {required} distinct "
                            f"authoritative sources before you may synthesize a package "
                            f"a production ops team can trust.\n\n"
                            f"Continue researching NOW: call web_search for an angle you "
                            f"haven't explored (a different vendor's docs, CIS Benchmark, "
                            f"MITRE ATT&CK/CWE, or the OS/language-ecosystem security "
                            f"advisory) and url_fetch a Tier-1/2 result. Do not emit JSON "
                            f"until you have ≥ {required} url_fetch calls of substantive "
                            f"(non-EMPTY, non-THIN) content. Marketplace / product / "
                            f"pricing / console pages do NOT count."
                        )
                    )
                )
                continue  # LLM will now do more research

            # Floor met OR budget nearly out — accept the finish attempt
            final_text = response.content or ""
            parsed = _try_parse_final_answer(
                final_text if isinstance(final_text, str) else json.dumps(final_text),
                run_id=run_id,
                emit_fn=emit_fn,
                context="loop-final",
            )
            if parsed is not None:
                emit_fn(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"✓ Agent produced draft package — {budget.summary()}",
                )
                # Depth retry: expand pathways that fell short of family minimum
                parsed = _maybe_expand_for_depth(
                    parsed,
                    family,
                    llm,
                    messages,
                    run_id,
                    emit_fn,
                    budget,
                )
                # Enterprise safety: cross-source consensus + destructive scan
                report = verify_output(
                    parsed, budget=budget, run_id=run_id, emit_fn=emit_fn, family=family
                )
                # Generic placeholder retry — LLM decides discovery cmd vs drop
                parsed, report = _maybe_expand_for_placeholders(
                    parsed,
                    report,
                    llm,
                    messages,
                    run_id,
                    emit_fn,
                )
                return (parsed, report)
            # Fall through to synthesis backup below
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                "Agent produced final answer but not parseable JSON — attempting synthesis pass",
            )
            return _synthesize_backup(llm, messages, run_id, emit_fn, budget, family)

        # Execute each tool call
        budget_exhausted = False
        for tc in tool_calls:
            tool_name = tc["name"]
            tool_args = tc.get("args", {}) or {}
            tool_call_id = tc["id"]

            selected_tool = next((t for t in tools if t.name == tool_name), None)
            if selected_tool is None:
                messages.append(
                    ToolMessage(
                        content=f"Error: unknown tool '{tool_name}'",
                        tool_call_id=tool_call_id,
                    )
                )
                continue

            try:
                observation = selected_tool.invoke(tool_args)
                messages.append(ToolMessage(content=str(observation), tool_call_id=tool_call_id))
            except RuntimeError as e:
                # Budget cap or tool-level failure — tell the LLM so it can adapt.
                err_msg = str(e)
                messages.append(
                    ToolMessage(
                        content=f"Tool error: {err_msg}",
                        tool_call_id=tool_call_id,
                    )
                )
                if "cap" in err_msg.lower() or "denied" in err_msg.lower():
                    budget_exhausted = True

        if budget_exhausted:
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"Budget exhausted mid-loop ({budget.summary()}) — forcing synthesis",
            )
            return _synthesize_backup(llm, messages, run_id, emit_fn, budget, _family_for_verify)

    # Loop exhausted without a final answer — force synthesis
    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"Max iterations ({max_iterations}) reached — forcing synthesis. {budget.summary()}",
    )
    return _synthesize_backup(llm, messages, run_id, emit_fn, budget, _family_for_verify)


# =============================================================================
# Synthesis backup — used when agent doesn't emit valid JSON in the loop
# =============================================================================
def _synthesize_backup(
    llm,
    messages: list[Any],
    run_id: str,
    emit_fn,
    budget: AgentBudget,
    family: str | None = None,
) -> AgentResult:
    """Ask the LLM to produce ONLY the JSON output, using structured_output
    to force schema compliance. Uses the message history for context —
    everything the agent has already learned from tools carries over.
    """
    # NOTE: same schema-strict caveat as _maybe_expand_for_depth — use raw
    # invoke + JSON parse instead of with_structured_output, because
    # LLMRemediationOutput has dict[str, Any] fields OpenAI strict rejects.
    try:
        synth_messages = messages + [
            HumanMessage(
                content=(
                    "Now produce the final RemediationPackage as a single JSON object "
                    "matching the schema in the system prompt. Every source_url MUST be "
                    "one of the URLs you called url_fetch on during this run. No prose, "
                    "just the JSON."
                )
            )
        ]
        response = llm.invoke(synth_messages)
        text = (
            response.content if isinstance(response.content, str) else json.dumps(response.content)
        )
        result = _try_parse_final_answer(
            text,
            run_id=run_id,
            emit_fn=emit_fn,
            context="synthesis-backup",
        )
        if result is None:
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                "Synthesis pass returned non-parseable content — no package produced",
            )
            return None
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"✓ Synthesis pass succeeded — {budget.summary()}",
        )
        # Depth retry: expand if the backup synthesis under-produced.
        result = _maybe_expand_for_depth(
            result,
            family,
            llm,
            messages,
            run_id,
            emit_fn,
            budget,
        )
        # Same enterprise safety pass whether we came from the loop or the backup.
        report = verify_output(result, budget=budget, run_id=run_id, emit_fn=emit_fn, family=family)
        # Generic placeholder retry — LLM decides discovery cmd vs drop
        result, report = _maybe_expand_for_placeholders(
            result,
            report,
            llm,
            messages,
            run_id,
            emit_fn,
        )
        return (result, report)
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Synthesis pass failed: {type(e).__name__}: {str(e)[:200]}",
        )
        return None
