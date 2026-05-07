from datetime import UTC, datetime, timedelta

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .agents.master import run_master
from .db import supabase_admin
from .models import RunCreated, TriggerEvent

# Don't accept a new run for the same scanner-set if there's already an
# in-flight (queued or running) run created within this window. Stops
# rapid-click / retry storms from spawning duplicate runs.
_DUPLICATE_WINDOW_SECONDS = 30


app = FastAPI(title="Agentic_VOP API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/agents/trigger", response_model=RunCreated, status_code=201)
def trigger_run(payload: TriggerEvent, background_tasks: BackgroundTasks) -> RunCreated:
    """Receive a user trigger from the UI; persist as a row in agent_runs and
    kick off the Master agent in the background.

    Two layers of dedup:
      1. Idempotency on event_id — same event_id returns the original run.
      2. Recent in-flight check — if a run for the same scanners is queued or
         running and was started within `_DUPLICATE_WINDOW_SECONDS`, return
         that run instead of creating a new one. Catches rapid double-clicks,
         network retries, etc.
    """
    sb = supabase_admin()

    # Layer 1 — exact event_id match
    existing = (
        sb.table("agent_runs")
        .select("run_id, event_id, status")
        .eq("event_id", payload.event_id)
        .limit(1)
        .execute()
    )
    if existing.data:
        return RunCreated(**existing.data[0])

    # Layer 2 — same-scanners in-flight within the dedup window
    cutoff = datetime.now(UTC) - timedelta(seconds=_DUPLICATE_WINDOW_SECONDS)
    recent = (
        sb.table("agent_runs")
        .select("run_id, event_id, status, targets, started_at")
        .in_("status", ["queued", "running"])
        .gte("started_at", cutoff.isoformat())
        .order("started_at", desc=True)
        .limit(20)
        .execute()
        .data
        or []
    )
    requested_scanners = set(payload.targets.scanners)
    for run in recent:
        run_scanners = set((run.get("targets") or {}).get("scanners") or [])
        if run_scanners == requested_scanners:
            # Same scanners, recent, in flight — return the existing run
            return RunCreated(
                run_id=run["run_id"],
                event_id=run["event_id"],
                status=run["status"],
            )

    # Otherwise — create a fresh run and kick off the Master agent
    insert = (
        sb.table("agent_runs")
        .insert(
            {
                "event_id": payload.event_id,
                "triggered_by": payload.persona,
                "action": payload.action,
                "targets": payload.targets.model_dump(),
                "status": "queued",
            }
        )
        .execute()
    )
    if not insert.data:
        raise HTTPException(status_code=500, detail="Failed to create run")

    row = insert.data[0]
    background_tasks.add_task(run_master, row["run_id"])

    return RunCreated(
        run_id=row["run_id"],
        event_id=row["event_id"],
        status=row["status"],
    )
