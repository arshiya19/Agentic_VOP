from typing import Any

from ..db import supabase_admin


def emit_trace(
    run_id: str,
    agent: str,  # "master" | "sub-agent-1" | "sub-agent-2" | "system"
    event_type: str,  # "DISPATCH" | "MESSAGE" | "DONE" | "ERROR"
    message: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Insert one row into agent_trace_events. Realtime pushes it to subscribed clients."""
    sb = supabase_admin()
    sb.table("agent_trace_events").insert(
        {
            "run_id": run_id,
            "agent": agent,
            "event_type": event_type,
            "message": message,
            "payload": payload,
        }
    ).execute()


def is_cancellation_requested(run_id: str) -> bool:
    """Check if a user has clicked Stop on this run.

    Polled at checkpoints by Master + Sub-Agents to exit early. Errors
    return False (fail-open) so a transient DB hiccup doesn't kill a run.
    """
    if not run_id:
        return False
    try:
        sb = supabase_admin()
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


class RunCancelledError(Exception):
    """Raised by agents when they detect a cancellation request and want
    to bail out of the current run cleanly."""
