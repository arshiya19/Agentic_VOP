"""Master Agent — LangGraph state machine (supervisor / orchestrator).

The Master is expressed as a LangGraph `StateGraph` with these nodes:

    load_context  → fetch run / prompt / connector registry from Supabase
    plan          → 1× LLM call → MasterPlan via ChatOpenAI.with_structured_output
    dispatch      → conditional edge: route to fetch / enrich / summarize / fail
    fetch         → invoke Sub-Agent 1 for the current FETCH step
    enrich        → invoke Sub-Agent 2 for the current ENRICH step
    summarize     → mark run completed, emit SCAN_COMPLETE + token summary
    fail          → mark run failed (terminal on error)

Why LangGraph:
  - The previous for-loop was already a state machine in disguise. This makes
    routing (FETCH vs ENRICH vs DONE) explicit instead of buried in if/else.
  - Easy to add conditional shortcuts later (skip ENRICH if 0 findings).
  - Compatible with checkpointers if/when we want resume-on-failure.

Triggered as a FastAPI BackgroundTask from POST /agents/trigger via
`run_master(run_id)`, which compiles the graph and calls `.invoke(...)`.
"""

from datetime import UTC, datetime
from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from ..db import supabase_admin
from ..models import MasterPlan
from . import sub_agent_1, sub_agent_2
from .llm import get_chat_llm
from .trace import emit_trace


# ============================================================================
# Graph state
# ============================================================================


class MasterState(TypedDict, total=False):
    """Shared state that flows through every node.

    Total=False lets nodes return partial updates — LangGraph merges them.
    """

    run_id: str
    run: dict  # the agent_runs row
    prompt_row: dict  # active prompt_db row for "master"
    available_tools: list[dict]  # filtered connection_registry rows
    plan: MasterPlan | None
    plan_usage: dict  # token counts for the plan LLM call

    # Step pointer for the dispatch loop
    step_idx: int

    # Per-scanner counts (keyed by tool name)
    per_scanner: dict[str, dict]
    total_inserted: int

    # Aggregated Sub-1 token counts (sum over all rows / all FETCH steps)
    sa1_tokens: dict

    # Last ENRICH result (single ENRICH step per run is typical)
    enrich_result: dict

    # Correlation id used in trace payloads
    correlation_id: str

    # Error path
    error_message: str | None


# ============================================================================
# Nodes
# ============================================================================


def _load_context_node(state: MasterState) -> dict:
    """Mark run as running, load DB context, emit DISPATCH trace."""
    run_id = state["run_id"]
    sb = supabase_admin()

    sb.table("agent_runs").update({"status": "running"}).eq("run_id", run_id).execute()
    emit_trace(run_id, "master", "DISPATCH", "Run started, planning")

    run = (
        sb.table("agent_runs")
        .select("*")
        .eq("run_id", run_id)
        .single()
        .execute()
        .data
    )
    prompt_row = (
        sb.table("prompt_db")
        .select("*")
        .eq("agent", "master")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )
    registry_rows = (
        sb.table("connection_registry")
        .select("tool, protocol, metadata")
        .eq("enabled", True)
        .execute()
        .data
        or []
    )
    available_tools = [
        {
            "tool": r["tool"],
            "protocol": r["protocol"],
            "connector_type": (r.get("metadata") or {}).get("connector_type"),
        }
        for r in registry_rows
    ]

    return {
        "run": run,
        "prompt_row": prompt_row,
        "available_tools": available_tools,
        "step_idx": 0,
        "per_scanner": {},
        "total_inserted": 0,
        "sa1_tokens": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "enrich_result": {},
        "correlation_id": f"corr-{run_id[:8]}",
    }


def _plan_node(state: MasterState) -> dict:
    """Single LLM call that produces a structured MasterPlan."""
    run_id = state["run_id"]
    prompt_row = state["prompt_row"]
    params = prompt_row.get("parameters") or {}

    llm = get_chat_llm(
        run_id=run_id,
        agent="master",
        model=prompt_row["model"],
        temperature=float(params.get("temperature", 0.1)),
        max_tokens=int(params.get("max_tokens", 1000)),
    )

    user_payload: dict[str, Any] = {
        "trigger": {
            "event_id": state["run"].get("event_id"),
            "action": state["run"].get("action"),
            "persona": state["run"].get("triggered_by"),
            "targets": state["run"].get("targets") or {},
        },
        "available_tools": state["available_tools"],
    }

    # Use structured output to bind MasterPlan as the response schema.
    # include_raw=True so we can read token usage from the raw response
    # if we ever need it directly (the callback already emits TOKEN_USAGE).
    structured_llm = llm.with_structured_output(MasterPlan, include_raw=False)
    plan: MasterPlan = structured_llm.invoke(
        [
            SystemMessage(content=prompt_row["prompt_text"]),
            HumanMessage(content=str(user_payload)),
        ]
    )

    emit_trace(
        run_id,
        "master",
        "MESSAGE",
        f"Plan ({len(plan.steps)} step(s)): {plan.plan_summary}",
        payload={"plan": plan.model_dump()},
    )

    # Token usage is emitted via the callback in get_chat_llm; we still
    # carry an empty dict here so the summarize node has a stable shape.
    return {"plan": plan, "plan_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def _route_after_dispatch(state: MasterState) -> str:
    """Conditional edge: pick the next node based on the current step kind."""
    plan = state["plan"]
    idx = state["step_idx"]
    if plan is None or idx >= len(plan.steps):
        return "summarize"
    return "fetch" if plan.steps[idx].kind == "FETCH" else "enrich"


def _fetch_node(state: MasterState) -> dict:
    """Execute one FETCH step by invoking Sub-Agent 1."""
    run_id = state["run_id"]
    sb = supabase_admin()
    idx = state["step_idx"]
    step = state["plan"].steps[idx]
    step_label = f"Step {idx + 1}/{len(state['plan'].steps)}"

    tool = step.tool
    per_scanner = dict(state["per_scanner"])

    if not tool:
        emit_trace(run_id, "master", "ERROR", f"{step_label}: FETCH step missing 'tool', skipping")
        return {"step_idx": idx + 1, "per_scanner": per_scanner}

    registry_result = (
        sb.table("connection_registry").select("*").eq("tool", tool).limit(1).execute()
    )
    registry_row = registry_result.data[0] if registry_result and registry_result.data else None
    if not registry_row:
        emit_trace(
            run_id,
            "master",
            "ERROR",
            f"{step_label}: no connector for tool '{tool}', skipping",
        )
        per_scanner[tool] = {"error": "no connector", "inserted": 0}
        return {"step_idx": idx + 1, "per_scanner": per_scanner}

    emit_trace(
        run_id,
        "master",
        "DISPATCH",
        f"{step_label}: FETCH from {tool} — {step.notes or ''}",
        payload={
            "action": "FETCH",
            "scan_id": run_id,
            "sub_agent_id": "sub-agent-1",
            "tool": tool,
            "protocol": registry_row["protocol"],
            "correlation_id": state["correlation_id"],
            "step_notes": step.notes,
        },
    )

    sa1_tokens = dict(state["sa1_tokens"])
    total_inserted = state["total_inserted"]

    try:
        inserted, sa1_tok = sub_agent_1.run_fetch(run_id, tool, registry_row)
        per_scanner[tool] = {"inserted": inserted}
        total_inserted += inserted
        sa1_tokens["prompt_tokens"] += sa1_tok.get("prompt_tokens", 0)
        sa1_tokens["completion_tokens"] += sa1_tok.get("completion_tokens", 0)
        sa1_tokens["total_tokens"] += sa1_tok.get("total_tokens", 0)
    except Exception as e:
        emit_trace(
            run_id,
            "master",
            "ERROR",
            f"Sub-Agent 1 failed for tool '{tool}': {type(e).__name__}: {str(e)[:300]}",
        )
        per_scanner[tool] = {"error": str(e)[:200], "inserted": 0}
        return {
            "step_idx": idx + 1,
            "per_scanner": per_scanner,
            "total_inserted": total_inserted,
            "sa1_tokens": sa1_tokens,
        }

    emit_trace(
        run_id,
        "master",
        "MESSAGE",
        f"Received FETCH_DONE for {tool} — {per_scanner[tool]['inserted']} canonical Issues",
        payload={
            "received_from": "sub-agent-1",
            "tool": tool,
            "records_inserted": per_scanner[tool]["inserted"],
            "correlation_id": state["correlation_id"],
        },
    )

    return {
        "step_idx": idx + 1,
        "per_scanner": per_scanner,
        "total_inserted": total_inserted,
        "sa1_tokens": sa1_tokens,
    }


def _enrich_node(state: MasterState) -> dict:
    """Execute one ENRICH step by invoking Sub-Agent 2."""
    run_id = state["run_id"]
    idx = state["step_idx"]
    step = state["plan"].steps[idx]
    step_label = f"Step {idx + 1}/{len(state['plan'].steps)}"

    emit_trace(
        run_id,
        "master",
        "DISPATCH",
        f"{step_label}: ENRICH — {step.notes or ''}",
        payload={
            "action": "ENRICH",
            "scan_id": run_id,
            "sub_agent_id": "sub-agent-2",
            "correlation_id": state["correlation_id"],
            "step_notes": step.notes,
        },
    )

    try:
        enrich_result = sub_agent_2.run_enrich(run_id)
    except Exception as e:
        emit_trace(
            run_id,
            "master",
            "ERROR",
            f"Sub-Agent 2 failed: {type(e).__name__}: {str(e)[:300]}",
        )
        enrich_result = {"enriched": 0, "error": str(e)[:200]}

    emit_trace(
        run_id,
        "master",
        "MESSAGE",
        f"Received ENRICH_DONE — {enrich_result.get('enriched', 0)} issues enriched "
        f"(EPSS: {enrich_result.get('epss_hits', 0)}, "
        f"KEV: {enrich_result.get('kev_hits', 0)}, "
        f"NVD: {enrich_result.get('nvd_hits', 0)})",
        payload={
            "received_from": "sub-agent-2",
            "enrich_result": enrich_result,
            "correlation_id": state["correlation_id"],
        },
    )

    return {"step_idx": idx + 1, "enrich_result": enrich_result}


def _summarize_node(state: MasterState) -> dict:
    """Mark run completed, write summary, emit token summary + SCAN_COMPLETE."""
    run_id = state["run_id"]
    sb = supabase_admin()

    plan = state["plan"]
    total_inserted = state["total_inserted"]
    per_scanner = state["per_scanner"]
    enrich_result = state["enrich_result"]
    sa1_tokens = state["sa1_tokens"]
    plan_usage = state["plan_usage"]

    sb.table("agent_runs").update(
        {
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
            "summary": {
                "plan": plan.model_dump() if plan else {},
                "total_findings": total_inserted,
                "per_scanner": per_scanner,
                "enriched": enrich_result.get("enriched", 0),
                "epss_hits": enrich_result.get("epss_hits", 0),
                "kev_hits": enrich_result.get("kev_hits", 0),
                "nvd_hits": enrich_result.get("nvd_hits", 0),
            },
        }
    ).eq("run_id", run_id).execute()

    sa2_tokens = {
        "prompt_tokens": enrich_result.get("prompt_tokens", 0),
        "completion_tokens": enrich_result.get("completion_tokens", 0),
        "total_tokens": enrich_result.get("total_tokens", 0),
    }

    emit_trace(
        run_id,
        "master",
        "MESSAGE",
        f"Token consumption summary — "
        f"Master: {plan_usage.get('total_tokens', 0)} | "
        f"Sub-Agent 1: {sa1_tokens['total_tokens']} | "
        f"Sub-Agent 2: {sa2_tokens['total_tokens']}",
        payload={
            "event_subtype": "TOKEN_SUMMARY",
            "master": plan_usage,
            "sub_agent_1": sa1_tokens,
            "sub_agent_2": sa2_tokens,
            "grand_total": (
                plan_usage.get("total_tokens", 0)
                + sa1_tokens["total_tokens"]
                + sa2_tokens["total_tokens"]
            ),
        },
    )

    emit_trace(
        run_id,
        "master",
        "MESSAGE",
        f"SCAN_COMPLETE — {total_inserted} findings, "
        f"{enrich_result.get('enriched', 0)} enriched.",
        payload={
            "event_type": "SCAN_COMPLETE",
            "scan_id": run_id,
            "summary": {
                "total_findings": total_inserted,
                "enriched": enrich_result.get("enriched", 0),
            },
            "correlation_id": state["correlation_id"],
        },
    )

    return {}


def _fail_node(state: MasterState) -> dict:
    """Terminal node on unhandled exceptions in the graph itself."""
    run_id = state["run_id"]
    sb = supabase_admin()

    emit_trace(
        run_id,
        "master",
        "ERROR",
        f"Run failed: {state.get('error_message') or 'unknown error'}",
    )
    sb.table("agent_runs").update(
        {
            "status": "failed",
            "completed_at": datetime.now(UTC).isoformat(),
        }
    ).eq("run_id", run_id).execute()
    return {}


# ============================================================================
# Graph wiring
# ============================================================================


def _build_graph():
    """Compile the Master state machine once, at import time."""
    graph = StateGraph(MasterState)

    graph.add_node("load_context", _load_context_node)
    graph.add_node("plan", _plan_node)
    graph.add_node("fetch", _fetch_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("summarize", _summarize_node)
    graph.add_node("fail", _fail_node)

    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "plan")

    # After plan: route by current step kind. fetch / enrich loop back here.
    graph.add_conditional_edges(
        "plan",
        _route_after_dispatch,
        {"fetch": "fetch", "enrich": "enrich", "summarize": "summarize"},
    )
    graph.add_conditional_edges(
        "fetch",
        _route_after_dispatch,
        {"fetch": "fetch", "enrich": "enrich", "summarize": "summarize"},
    )
    graph.add_conditional_edges(
        "enrich",
        _route_after_dispatch,
        {"fetch": "fetch", "enrich": "enrich", "summarize": "summarize"},
    )

    graph.add_edge("summarize", END)
    graph.add_edge("fail", END)

    return graph.compile()


_MASTER_GRAPH = _build_graph()


# ============================================================================
# Public entrypoint — kept stable so main.py / BackgroundTasks need no change
# ============================================================================


def run_master(run_id: str) -> None:
    """Compile-once graph, invoke per run. Falls back to _fail_node on exception."""
    try:
        _MASTER_GRAPH.invoke({"run_id": run_id})
    except Exception as e:
        # Last-resort safety net: graph itself blew up before reaching summarize/fail.
        _fail_node({"run_id": run_id, "error_message": f"{type(e).__name__}: {str(e)[:300]}"})
