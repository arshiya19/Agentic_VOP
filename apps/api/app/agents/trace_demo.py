"""Trace helpers scoped to the `demo` Postgres schema.

Mirrors `apps/api/app/agents/trace.py` but writes to `demo.agent_trace_events`
and reads `demo.agent_runs`. Used exclusively by the demo pipeline
(master_demo.py + sub_agent_*_demo.py + planner_demo.py) so real trace.py
stays byte-identical — see [[agentic-vop-demo-pipeline-architecture]].
"""

from typing import Any

from ..db import supabase_admin_demo
from .trace import RunCancelledError  # re-export so demo callers don't cross-import


__all__ = ["emit_trace_demo", "is_cancellation_requested_demo", "RunCancelledError"]


def emit_trace_demo(
    run_id: str,
    agent: str,  # "master" | "sub-agent-1" | "sub-agent-2" | "sub-agent-3" | "system"
    event_type: str,  # "DISPATCH" | "MESSAGE" | "DONE" | "ERROR"
    message: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Insert one row into demo.agent_trace_events. Same shape as emit_trace()."""
    sb = supabase_admin_demo()
    sb.table("agent_trace_events").insert(
        {
            "run_id": run_id,
            "agent": agent,
            "event_type": event_type,
            "message": message,
            "payload": payload,
        }
    ).execute()


def is_cancellation_requested_demo(run_id: str) -> bool:
    """Check if a user has clicked Stop on this demo run. Reads demo.agent_runs."""
    if not run_id:
        return False
    try:
        sb = supabase_admin_demo()
        row = (
            sb.table("agent_runs")
            .select("cancellation_requested")
            .eq("run_id", run_id)
            .single()
            .execute()
            .data
        )
        return bool(row and row.get("cancellation_requested"))
    except Exception:  # noqa: BLE001 — DB hiccup shouldn't kill the run
        return False
