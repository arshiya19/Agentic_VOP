"""SA-3 AGENTIC runner — tool-calling loop with per-tool metric capture.

This wraps the production `run_agentic_planner` from agent_v2.py (not the
simpler hybrid single-call path used by sa3_runner.py). The agentic path
goes through a multi-turn tool loop:

   LLM asks for web_search → runs it → feeds result back
   LLM asks for url_fetch  → runs it → feeds result back
   LLM asks for file_fetch → runs it → feeds result back
   ... until LLM proposes a RemediationPackage within budget

The additional metrics we capture (Nikhil's agent-specific ask):
  tool_call_count          — total tool invocations
  tools_used               — list of distinct tool names
  web_search_calls         — how many web searches
  url_fetch_calls          — how many URL fetches
  file_fetch_calls         — how many file fetches
  tool_budget_remaining    — unused budget
  tool_cost_usd_accrued    — $ accrued on tool calls (web_search ≈ $0.015 ea)

Budget capture mechanism: monkey-patch AgentBudget to also register the
instance in a module-level dict keyed by run_id. Benchmarks run serially,
so there's no race. After `run_agentic_planner` returns, we read the
budget back.
"""

from __future__ import annotations

import time
from typing import Any

from apps.api.app.agents.remediation import agent_v2, tools
from apps.api.app.agents.remediation import prompt_router
from apps.api.app.agents.remediation.tools.budget import AgentBudget
from apps.api.app.config import settings
from apps.api.app.db import supabase_admin


# ─── Budget capture via monkey-patch ─────────────────────────────────────
_BUDGETS_BY_RUN: dict[str, AgentBudget] = {}
_original_record_call = AgentBudget.record_call
_patched = False


# ─── Model-override via monkey-patch of load_sa3_prompt ──────────────────
# run_agentic_planner reads the model name from `prompt_row["model"]` which
# comes from `prompt_router.load_sa3_prompt`. To actually swap the model
# per benchmark call, we wrap that function so the returned prompt_row's
# `model` field is overridden with whatever `--model` was passed.
#
# Also overrides the `fallback_model` in `parameters` so the retry chain
# doesn't silently fall back to a different model mid-run.
_original_load_sa3_prompt = prompt_router.load_sa3_prompt
_model_override: list[str | None] = [None]
_prompt_patched = False


def _install_prompt_patch() -> None:
    """Wrap load_sa3_prompt so it swaps the model in the returned row."""
    global _prompt_patched
    if _prompt_patched:
        return

    def _patched_load_sa3_prompt(*args, **kwargs):
        prompt_row = _original_load_sa3_prompt(*args, **kwargs)
        override = _model_override[0]
        if override and isinstance(prompt_row, dict):
            prompt_row = dict(prompt_row)
            prompt_row["model"] = override
            params = dict(prompt_row.get("parameters") or {})
            params["fallback_model"] = override
            prompt_row["parameters"] = params
        return prompt_row

    prompt_router.load_sa3_prompt = _patched_load_sa3_prompt
    # agent_v2 imported the function by name at module-load time → also
    # patch the reference in that module so the already-loaded run_agentic
    # path sees the override.
    try:
        agent_v2.load_sa3_prompt = _patched_load_sa3_prompt  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001, S110
        pass
    _prompt_patched = True


def _install_budget_patch() -> None:
    """Attach a side-effect to AgentBudget.record_call so we can read the
    budget state back after the agentic call completes. Idempotent."""
    global _patched
    if _patched:
        return

    _current_run_id: list[str] = ["unknown"]

    def _patched_record_call(self, tool: str) -> None:
        _original_record_call(self, tool)
        _BUDGETS_BY_RUN[_current_run_id[0]] = self

    # Expose a setter so the runner can tag the run_id before each dispatch.
    def _set_run_id(run_id: str) -> None:
        _current_run_id[0] = run_id

    AgentBudget.record_call = _patched_record_call  # type: ignore[method-assign]
    _install_budget_patch._set_run_id = _set_run_id  # type: ignore[attr-defined]
    _patched = True


def run_sa3_agentic_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,  # noqa: ARG001
    scanner: str,
    fixture_input: dict | None = None,
    **_ignored: Any,
) -> dict[str, Any]:
    """Call SA-3 agentic planner against a derived SA-3 fixture.

    The `model` argument IS honored: we monkey-patch load_sa3_prompt so the
    prompt_row returned to run_agentic_planner has its `model` field
    overridden. Pass claude-sonnet-4-6 or gemini-2.0-pro and the agentic
    tool loop will actually use that model.
    """
    if not fixture_input or "issue" not in fixture_input:
        raise ValueError(
            "SA-3 agentic fixtures must provide an 'input' block with 'issue', 'asset', 'family'"
        )

    issue = fixture_input["issue"]
    asset = fixture_input.get("asset") or {}
    family = fixture_input.get("family") or "os_vulnerability"

    sb = supabase_admin()
    _install_budget_patch()
    _install_budget_patch._set_run_id(run_id)  # type: ignore[attr-defined]
    _install_prompt_patch()
    _model_override[0] = model  # swap the model seen by run_agentic_planner

    original_trace = settings.trace_token_usage
    settings.trace_token_usage = False

    started = time.perf_counter()
    result: Any = None
    plan: Any = None  # the LLMRemediationOutput part of the tuple
    error: str | None = None
    failure_mode: str | None = None

    try:
        # run_agentic_planner returns tuple[LLMRemediationOutput, VerificationReport] | None
        result = agent_v2.run_agentic_planner(
            issue=issue,
            asset=asset,
            family=family,
            run_id=run_id,
            sb_pub=sb,
            emit_fn=lambda *a, **kw: None,
        )
        if result is not None:
            plan = result[0] if isinstance(result, tuple) else result
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e)[:300]}"
        failure_mode = "agentic_error"
    finally:
        settings.trace_token_usage = original_trace
        _model_override[0] = None  # don't leak into the next call

    latency_ms = int((time.perf_counter() - started) * 1000)

    # Read budget back from the patched registry
    budget = _BUDGETS_BY_RUN.pop(run_id, None)
    if budget:
        tool_call_count = budget.call_count
        tool_cost_usd_accrued = round(budget.cost_accrued_usd, 4)
        by_tool = dict(budget.by_tool)
        tools_used = ",".join(sorted(by_tool.keys()))
        web_calls = by_tool.get("web_search", 0)
        url_calls = by_tool.get("url_fetch", 0)
        file_calls = by_tool.get("file_fetch", 0)
        budget_remaining = max(0, budget.max_calls - budget.call_count)
    else:
        tool_call_count = 0
        tool_cost_usd_accrued = 0.0
        tools_used = ""
        web_calls = url_calls = file_calls = 0
        budget_remaining = 0

    # Pathway shape (same extras as hybrid SA-3 runner)
    pathways_count = 0
    recommended_steps = 0
    if plan is not None and hasattr(plan, "pathways"):
        pathways_count = len(plan.pathways or [])
        if pathways_count:
            recommended_steps = len(plan.pathways[0].remediation_steps or [])

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": latency_ms,
        "input_chars": len(str(fixture_input)),
        # No per-call token sum here — agentic path makes many LLM calls, token
        # totals are in the budget. Report tool cost separately as cost_usd.
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "retries": 0,
        "schema_valid": plan is not None,
        "failure_mode": failure_mode,
        "error": error,
        "output": plan.model_dump() if plan and hasattr(plan, "model_dump") else None,
        # Hybrid-SA-3 extras
        "pathways_count": pathways_count,
        "recommended_steps": recommended_steps,
        # Agentic-specific extras
        "tool_call_count": tool_call_count,
        "tools_used": tools_used,
        "web_search_calls": web_calls,
        "url_fetch_calls": url_calls,
        "file_fetch_calls": file_calls,
        "tool_budget_remaining": budget_remaining,
        "tool_cost_usd_accrued": tool_cost_usd_accrued,
    }


# Silence unused-import linter — the tools module is loaded so the patch
# can take effect even if agent_v2 is imported first.
_ = tools
