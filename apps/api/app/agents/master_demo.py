"""Master — DEMO orchestrator.

LangGraph shape:
  START → load_context → sample → enrich → remediate → fix → summarize → END

The demo pipeline seeds `demo.issues` by SAMPLING 1 issue per family from
real -ec2 issues in `public.issues` (see sample_from_real.py). Enrichment,
remediation (SA3), and execution (SA4) then run against those copied rows,
isolated in demo schema.

Differences vs real master.py:
  - No planning step — fixed sequence, no LLM plan needed.
  - No FETCH step — real fetch already ran and populated public.issues with
    -ec2 sources; the demo just samples from those.
  - Adds a REMEDIATE step (via planner_demo) after enrichment.
  - Adds a FIX step (Sub-Agent 4) after remediation — auto-chained per
    settings.fixer_auto_chain. Runs against env2 via SSM RunCommand.
  - All state reads/writes go through demo.* (via supabase_admin_demo()).

Run entry: run_demo_master(run_id) — mirrors run_master().
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from ..config import settings
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
    fix_result: dict
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
        "Demo pipeline started: sample -ec2 → enrich → remediate → fix",
    )
    return {
        "sample_result": {},
        "enrich_result": {},
        "remediation_result": {},
        "fix_result": {},
    }


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


def _fix_node(state: DemoMasterState) -> dict:
    """Sub-Agent 4 demo — auto-chained execution of every persisted package.

    Runs the fixer once per remediation_package created by this demo run.
    Sequential (one at a time) because env2 + terraform state can't be
    raced in parallel — see FixerConfig.allow_concurrent_runs.

    Two config toggles govern behavior:
      settings.fixer_auto_chain      — when False, skip the fixer entirely
                                        (useful pre-env2 provisioning)
      settings.fixer_env2_instance_id — when empty, skip + emit a warning
                                        (fail-soft, don't halt demo)
    """
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before fix stage")

    # Toggle 1 — auto-chain off?
    if not settings.fixer_auto_chain:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — settings.fixer_auto_chain is False",
        )
        return {"fix_result": {"skipped": True, "reason": "auto_chain_disabled"}}

    # Toggle 2 — no env2 configured?
    if not settings.fixer_env2_instance_id:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — FIXER_ENV2_INSTANCE_ID not set (env2 not provisioned yet)",
        )
        return {"fix_result": {"skipped": True, "reason": "env2_not_configured"}}

    # Load packages this demo run just persisted
    sb = supabase_admin_demo()
    pkg_rows = (
        sb.table("remediation_packages")
        .select("id, family, issue_id")
        .eq("agent_run_id", run_id)
        .execute()
        .data
        or []
    )

    if not pkg_rows:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — no packages to fix (upstream stage produced none)",
        )
        return {"fix_result": {"skipped": True, "reason": "no_packages"}}

    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Dispatching to Sub-Agent 4 (demo) — {len(pkg_rows)} package(s) to fix on env2",
    )

    # Import lazily so the demo module doesn't force the SA4 dependency graph
    # to import at module-load time (kept the fixer package light for tests).
    from .fixer import run_fixer  # noqa: PLC0415

    fix_runs: list[dict] = []
    succeeded = 0
    failed = 0
    rolled_back = 0

    for pkg in pkg_rows:
        if is_cancellation_requested_demo(run_id):
            raise RunCancelledError("Demo run cancelled during fix stage")

        try:
            fix_run_id = run_fixer(
                pkg["id"],
                agent_run_id=run_id,
                sb=sb,
                emit_fn=emit_trace_demo,
                environment="sandbox",
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "master",
                "ERROR",
                f"Sub-Agent 4 dispatch failed for package #{pkg['id']}: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )
            failed += 1
            fix_runs.append({"package_id": pkg["id"], "status": "dispatch_failed"})
            continue

        # Read back final status so summary can report accurately
        row = (
            sb.table("fix_runs").select("id, status").eq("id", fix_run_id).limit(1).execute().data
            or []
        )
        status = (row[0] if row else {}).get("status", "unknown")
        fix_runs.append({"package_id": pkg["id"], "fix_run_id": fix_run_id, "status": status})

        if status == "success":
            succeeded += 1
        elif status == "rolled_back":
            rolled_back += 1
        else:
            failed += 1

    result = {
        "skipped": False,
        "total": len(pkg_rows),
        "succeeded": succeeded,
        "failed": failed,
        "rolled_back": rolled_back,
        "fix_runs": fix_runs,
    }
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received FIX_DONE — {succeeded} succeeded, {rolled_back} rolled back, {failed} failed",
    )
    return {"fix_result": result}


def _summarize_node(state: DemoMasterState) -> dict:
    """Finalize the demo run — update agent_runs, emit DONE."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    sample = state.get("sample_result", {})
    enrich = state.get("enrich_result", {})
    remediation = state.get("remediation_result", {})
    fix = state.get("fix_result", {})

    sampled = sample.get("sampled", 0)

    sb.table("agent_runs").update(
        {
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
        }
    ).eq("run_id", run_id).execute()

    fix_summary = (
        "fix stage skipped"
        if fix.get("skipped")
        else f"{fix.get('succeeded', 0)} fixed"
        f" · {fix.get('rolled_back', 0)} rolled back"
        f" · {fix.get('failed', 0)} failed"
    )

    emit_trace_demo(
        run_id,
        "master",
        "DONE",
        f"DEMO_COMPLETE — {sampled} sampled · "
        f"{enrich.get('enriched', 0)} enriched · "
        f"{remediation.get('persisted', 0)} remediation package(s) generated · {fix_summary}",
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
            "fix_result": fix,
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
    graph.add_node("fix", _fix_node)
    graph.add_node("summarize", _summarize_node)
    graph.add_node("fail", _fail_node)

    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "sample")
    graph.add_edge("sample", "enrich")
    graph.add_edge("enrich", "remediate")
    graph.add_edge("remediate", "fix")
    graph.add_edge("fix", "summarize")
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
