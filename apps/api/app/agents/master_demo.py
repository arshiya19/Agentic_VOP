"""Master — DEMO orchestrator.

LangGraph shape:
  START → load_context → sample → enrich → remediate → summarize → END

The demo pipeline seeds `demo.issues` by SAMPLING 1 issue per family from
real -ec2 issues in `public.issues` (see sample_from_real.py). Enrichment
and remediation then run against those copied rows, isolated in demo schema.

Differences vs real master.py:
  - No planning step — fixed sequence, no LLM plan needed.
  - No FETCH step — real fetch already ran and populated public.issues with
    -ec2 sources; the demo just samples from those.
  - Adds a REMEDIATE step (via planner_demo) after enrichment.
  - All state reads/writes go through demo.* (via supabase_admin_demo()).

Run entry: run_demo_master(run_id) — mirrors run_master().
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from ..db import supabase_admin_demo
from .remediation import planner_demo
from .sample_from_real import sample_and_copy_ec2_issues
from .sub_agent_2_demo import run_demo_enrich
from .trace_demo import RunCancelledError, emit_trace_demo, is_cancellation_requested_demo


class DemoMasterState(TypedDict, total=False):
    run_id: str
    # ID of the linked real agent_run whose -ec2 output feeds sampling.
    # Optional — None means "sample across all -ec2 issues in the DB."
    real_run_id: str | None
    sample_result: dict
    enrich_result: dict
    remediation_result: dict
    error_message: str | None


def _load_context_node(state: DemoMasterState) -> dict:
    """Mark demo run as running, emit start trace."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    # The agent_runs row is created by the endpoint before graph invoke,
    # so this only flips status. If it doesn't exist yet, still emit trace.
    sb.table("agent_runs").update({"status": "running"}).eq("run_id", run_id).execute()

    emit_trace_demo(
        run_id,
        "master",
        "DISPATCH",
        "Demo pipeline started: sample -ec2 → enrich → remediate",
    )
    return {"sample_result": {}, "enrich_result": {}, "remediation_result": {}}


def _sample_node(state: DemoMasterState) -> dict:
    """Sample 1 real -ec2 issue per family and copy into demo.issues.

    If state.real_run_id is set, only samples from that specific real fetch's
    output — prevents pulling in unrelated stale -ec2 rows.
    """
    run_id = state["run_id"]
    real_run_id = state.get("real_run_id")
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before sampling")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sample-from-real")
    result = sample_and_copy_ec2_issues(run_id, real_run_id=real_run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received SAMPLE_DONE — {result.get('sampled', 0)} real -ec2 issue(s) "
        f"copied into demo.issues (families found: {result.get('families_found', [])})",
    )
    return {"sample_result": result}


def _enrich_node(state: DemoMasterState) -> dict:
    """Sub-Agent 2 demo — enrich the demo issues."""
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before enrichment")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sub-Agent 2 (demo)")
    result = run_demo_enrich(run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received ENRICH_DONE — {result.get('enriched', 0)} issue(s) enriched "
        f"(EPSS: {result.get('epss_hits', 0)}, "
        f"KEV: {result.get('kev_hits', 0)}, "
        f"NVD: {result.get('nvd_hits', 0)})",
    )
    return {"enrich_result": result}


def _remediate_node(state: DemoMasterState) -> dict:
    """Sub-Agent 3 demo — generate + persist RemediationPackages."""
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before remediation")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sub-Agent 3 (demo)")
    result = planner_demo.run_demo_remediation(run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received REMEDIATE_DONE — {result.get('persisted', 0)} package(s) persisted",
    )
    return {"remediation_result": result}


def _summarize_node(state: DemoMasterState) -> dict:
    """Finalize the demo run — update agent_runs, emit DONE."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    sample = state.get("sample_result", {})
    enrich = state.get("enrich_result", {})
    remediation = state.get("remediation_result", {})

    sampled = sample.get("sampled", 0)

    sb.table("agent_runs").update(
        {
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
        }
    ).eq("run_id", run_id).execute()

    emit_trace_demo(
        run_id,
        "master",
        "DONE",
        f"DEMO_COMPLETE — {sampled} sampled · "
        f"{enrich.get('enriched', 0)} enriched · "
        f"{remediation.get('persisted', 0)} remediation package(s) generated",
        payload={
            "from": "master",
            "status": "DEMO_COMPLETE",
            "scan_id": run_id,
            "records_sampled": sampled,
            "families_found": sample.get("families_found", []),
            "families_missing": sample.get("families_missing", []),
            "records_enriched": enrich.get("enriched", 0),
            "records_remediated": remediation.get("persisted", 0),
            "epss_hits": enrich.get("epss_hits", 0),
            "kev_hits": enrich.get("kev_hits", 0),
            "nvd_hits": enrich.get("nvd_hits", 0),
        },
    )
    return {}


def _fail_node(state: DemoMasterState) -> dict:
    """Mark demo run as failed. Stashes the error under summary.error since
    agent_runs has no dedicated error column (migration 0001 shape)."""
    run_id = state["run_id"]
    msg = state.get("error_message") or "Unknown error"
    sb = supabase_admin_demo()
    sb.table("agent_runs").update(
        {
            "status": "failed",
            "completed_at": datetime.now(UTC).isoformat(),
            "summary": {"error": msg[:1000], "from": "master_demo"},
        }
    ).eq("run_id", run_id).execute()
    emit_trace_demo(run_id, "master", "ERROR", f"Demo run failed: {msg[:300]}")
    return {}


# ============================================================================
# Graph
# ============================================================================


def _build_graph():
    graph = StateGraph(DemoMasterState)
    graph.add_node("load_context", _load_context_node)
    graph.add_node("sample", _sample_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("remediate", _remediate_node)
    graph.add_node("summarize", _summarize_node)
    graph.add_node("fail", _fail_node)

    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "sample")
    graph.add_edge("sample", "enrich")
    graph.add_edge("enrich", "remediate")
    graph.add_edge("remediate", "summarize")
    graph.add_edge("summarize", END)
    graph.add_edge("fail", END)

    return graph.compile()


_GRAPH = _build_graph()


def run_demo_master(run_id: str, real_run_id: str | None = None) -> None:
    """Compile-once graph, invoke per run. Falls back to _fail_node on exception.

    Args:
        run_id: the demo agent_run_id.
        real_run_id: optional — the linked real fetch's run_id whose -ec2 output
            we should sample from. When called from /agents/trigger_demo this
            is always set (chained flow); when called standalone it's None
            (samples across all -ec2 issues).
    """
    try:
        _GRAPH.invoke({"run_id": run_id, "real_run_id": real_run_id})
    except RunCancelledError:
        # Cancellation was already recorded by the sub-agent that detected it —
        # don't call _fail_node (which would overwrite the cancelled status).
        pass
    except Exception as e:  # noqa: BLE001
        _fail_node({"run_id": run_id, "error_message": f"{type(e).__name__}: {str(e)[:300]}"})
