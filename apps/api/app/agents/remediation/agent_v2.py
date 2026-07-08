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
from .verifier import verify_output


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
            Cleaned page content (up to 8000 chars, then truncated).
        """
        result = fetch_url(url, budget, run_id=run_id, emit_fn=emit_fn)
        return (
            f"# {result['title']}\n"
            f"# URL: {result['final_url']}\n\n"
            f"{result['text']}"
        )

    return [web_search_tool, url_fetch_tool]


# =============================================================================
# JSON extraction — the LLM's final message may or may not be pure JSON
# =============================================================================
def _try_parse_final_answer(text: str) -> LLMRemediationOutput | None:
    """Parse text as LLMRemediationOutput JSON. Handles common wrappings:
      - Bare JSON
      - JSON inside ```json ... ``` fences
      - JSON with leading/trailing prose (extract first {...} balanced block)
    """
    if not text or not text.strip():
        return None

    # 1. Try bare parse first
    for candidate in _candidate_json_slices(text):
        try:
            return LLMRemediationOutput.model_validate_json(candidate)
        except Exception:  # noqa: BLE001
            continue
    return None


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
) -> LLMRemediationOutput | None:
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
            run_id, "sub-agent-3", "ERROR",
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
        run_id, "sub-agent-3", "MESSAGE",
        f"🤖 Agentic remediation starting — family={family}, budget={budget.max_calls} calls / "
        f"${budget.max_cost_usd:.2f} — model={model} @ temp={temperature}",
    )

    # Build the initial context: issue + asset + family passed as JSON
    user_payload = {
        "issue": issue,
        "asset": asset,
        "family": family,
    }

    messages: list[Any] = [
        SystemMessage(content=prompt_row["prompt_text"]),
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
                run_id, "sub-agent-3", "ERROR",
                f"LLM call failed at iteration {iteration + 1}: {type(e).__name__}: {str(e)[:200]}",
            )
            return None

        messages.append(response)

        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            # Model didn't request tools — should be the final answer.
            final_text = response.content or ""
            parsed = _try_parse_final_answer(
                final_text if isinstance(final_text, str) else json.dumps(final_text)
            )
            if parsed is not None:
                emit_fn(
                    run_id, "sub-agent-3", "MESSAGE",
                    f"✓ Agent produced draft package — {budget.summary()}",
                )
                # Enterprise safety: cross-source consensus + destructive-pattern scan
                verify_output(parsed, budget=budget, run_id=run_id, emit_fn=emit_fn, family=family)
                return parsed
            # Fall through to synthesis backup below
            emit_fn(
                run_id, "sub-agent-3", "MESSAGE",
                "Agent produced final answer but not parseable JSON — attempting synthesis pass",
            )
            return _synthesize_backup(llm, messages, run_id, emit_fn, budget)

        # Execute each tool call
        budget_exhausted = False
        for tc in tool_calls:
            tool_name = tc["name"]
            tool_args = tc.get("args", {}) or {}
            tool_call_id = tc["id"]

            selected_tool = next((t for t in tools if t.name == tool_name), None)
            if selected_tool is None:
                messages.append(ToolMessage(
                    content=f"Error: unknown tool '{tool_name}'",
                    tool_call_id=tool_call_id,
                ))
                continue

            try:
                observation = selected_tool.invoke(tool_args)
                messages.append(ToolMessage(content=str(observation), tool_call_id=tool_call_id))
            except RuntimeError as e:
                # Budget cap or tool-level failure — tell the LLM so it can adapt.
                err_msg = str(e)
                messages.append(ToolMessage(
                    content=f"Tool error: {err_msg}",
                    tool_call_id=tool_call_id,
                ))
                if "cap" in err_msg.lower() or "denied" in err_msg.lower():
                    budget_exhausted = True

        if budget_exhausted:
            emit_fn(
                run_id, "sub-agent-3", "MESSAGE",
                f"Budget exhausted mid-loop ({budget.summary()}) — forcing synthesis",
            )
            return _synthesize_backup(llm, messages, run_id, emit_fn, budget, _family_for_verify)

    # Loop exhausted without a final answer — force synthesis
    emit_fn(
        run_id, "sub-agent-3", "MESSAGE",
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
) -> LLMRemediationOutput | None:
    """Ask the LLM to produce ONLY the JSON output, using structured_output
    to force schema compliance. Uses the message history for context —
    everything the agent has already learned from tools carries over.
    """
    try:
        # Nudge to focus on emitting valid JSON
        synth_messages = messages + [HumanMessage(content=(
            "Now produce the final RemediationPackage as a single JSON object "
            "matching the schema in the system prompt. Every source_url MUST be "
            "one of the URLs you called url_fetch on during this run. No prose, "
            "just the JSON."
        ))]
        structured = llm.with_structured_output(LLMRemediationOutput)
        result = structured.invoke(synth_messages)
        emit_fn(
            run_id, "sub-agent-3", "MESSAGE",
            f"✓ Synthesis pass succeeded — {budget.summary()}",
        )
        # Same enterprise safety pass whether we came from the loop or the backup.
        verify_output(result, budget=budget, run_id=run_id, emit_fn=emit_fn, family=family)
        return result
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id, "sub-agent-3", "ERROR",
            f"Synthesis pass failed: {type(e).__name__}: {str(e)[:200]}",
        )
        return None
