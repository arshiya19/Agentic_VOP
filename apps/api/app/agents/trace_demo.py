"""Trace helpers scoped to the `demo` Postgres schema.

Mirrors `apps/api/app/agents/trace.py` but writes to `demo.agent_trace_events`
and reads `demo.agent_runs`. Used exclusively by the demo pipeline
(master_demo.py + sub_agent_*_demo.py + planner_demo.py) so real trace.py
stays byte-identical — see [[agentic-vop-demo-pipeline-architecture]].

Also mirrors every demo trace event into a per-run log file at
`apps/api/logs/demo_runs/<YYYYMMDD_HHMMSS>_<run_id_short>.log`. The master
`agent_trace.log` still catches everything (unchanged); the per-run file
just makes it trivial to fetch a single run's timeline for debugging
without grep-ing the master log.
"""

import logging
import os
import time
from typing import Any

from ..db import supabase_admin_demo
from .trace import (  # re-export so demo callers don't cross-import
    RunCancelledError,
    _LOG_DIR,
)


__all__ = ["emit_trace_demo", "is_cancellation_requested_demo", "RunCancelledError"]


# =============================================================================
# Per-run log files — one file per demo run
# =============================================================================
# One file per run_id. Cached logger avoids reopening the file on every event
# (and prevents fd leak). Master log at trace._trace_logger is unchanged.
_DEMO_RUN_LOG_DIR = os.path.join(_LOG_DIR, "demo_runs")
os.makedirs(_DEMO_RUN_LOG_DIR, exist_ok=True)

_per_run_loggers: dict[str, logging.Logger] = {}


def _get_per_run_logger(run_id: str) -> logging.Logger | None:
    """Return a cached logger writing to demo_runs/<ts>_<run_id_short>.log.

    Real-time: FileHandler flushes after each emit (stdlib default) so
    events hit disk immediately — safe to tail during a live run.

    Fail-open: any filesystem hiccup returns None so the trace path
    (DB insert + master log) keeps working regardless.
    """
    if not run_id:
        return None
    cached = _per_run_loggers.get(run_id)
    if cached is not None:
        return cached
    try:
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        short = run_id.replace("-", "")[:8] if run_id else "unknown"
        path = os.path.join(_DEMO_RUN_LOG_DIR, f"{ts}_{short}.log")

        lg = logging.getLogger(f"demo_run.{run_id}")
        lg.setLevel(logging.DEBUG)
        lg.propagate = False  # Don't send events up to root or master logger

        # Only add handler once — Python caches Logger by name, so on cache
        # miss but existing handlers (rare, e.g. server hot-reload), skip.
        if not lg.handlers:
            fh = logging.FileHandler(path, mode="a", encoding="utf-8")
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            lg.addHandler(fh)

        _per_run_loggers[run_id] = lg
        return lg
    except Exception:  # noqa: BLE001 — never break the trace path
        return None


def emit_trace_demo(
    run_id: str,
    agent: str,  # "master" | "sub-agent-1" | "sub-agent-2" | "sub-agent-3" | "system"
    event_type: str,  # "DISPATCH" | "MESSAGE" | "DONE" | "ERROR"
    message: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Insert one row into demo.agent_trace_events. Same shape as emit_trace()."""
    # Master log (all runs, append-only) — unchanged behavior
    from .trace import _trace_logger  # noqa: PLC0415

    line = f"[{agent}] [{event_type}] {message}"
    _trace_logger.info(f"[DEMO] {line}")

    # Per-run log (best-effort, fail-open)
    per_run = _get_per_run_logger(run_id)
    if per_run is not None:
        try:
            per_run.info(line)
        except Exception:  # noqa: BLE001, S110 — file write hiccup shouldn't kill trace
            pass

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
