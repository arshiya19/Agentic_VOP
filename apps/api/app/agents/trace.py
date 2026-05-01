from typing import Any

from ..db import supabase_admin


def emit_trace(
    run_id: str,
    agent: str,                         # "master" | "sub-agent-1" | "sub-agent-2" | "system"
    event_type: str,                    # "DISPATCH" | "MESSAGE" | "DONE" | "ERROR"
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
