from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .agents.master import run_master
from .db import supabase_admin
from .models import RunCreated, TriggerEvent

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

    Idempotent on event_id — repeat calls with the same event_id return the original run
    and do NOT re-trigger the agents.
    """
    sb = supabase_admin()

    existing = (
        sb.table("agent_runs")
        .select("run_id, event_id, status")
        .eq("event_id", payload.event_id)
        .limit(1)
        .execute()
    )
    if existing.data:
        return RunCreated(**existing.data[0])

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

    # Kick off Master agent in the background — endpoint returns immediately
    background_tasks.add_task(run_master, row["run_id"])

    return RunCreated(
        run_id=row["run_id"],
        event_id=row["event_id"],
        status=row["status"],
    )
