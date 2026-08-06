from datetime import UTC, datetime, timedelta

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from concurrent.futures import ThreadPoolExecutor, as_completed

from .agents.connectors.file_upload import SCANNER_BUCKET, sniff_format
from .agents.master import run_master
from .agents.master_demo import run_demo_master
from .agents.remediation.planner import persist_package, plan_remediation
from .agents.sub_agent_1 import (
    extract_all_vectors_from_raw,
    parse_cvss_vector,
    pick_best_cvss_vector,
)
from .agents.sub_agent_2 import (
    SCORING_POLICY_VERSION,
    _build_asset_index,
    _compute_score,
    _fetch_nvd_data,
    _fetch_nvd_data_from_intelligence,
    _llm_decide,
    _resolve_asset,
    _write_back_nvd_to_dynamo,
)
from .config import settings
from .crypto import (
    encrypt_sensitive_fields,
    get_sensitive_fields,
    is_encryption_enabled,
    redact_sensitive_fields,
    validate_endpoint_security,
)
from .db import supabase_admin, supabase_admin_demo
from .mitre_refresh import refresh_mitre_attack, refresh_mitre_capec, refresh_mitre_cwe
from .models import RunCreated, TriggerEvent
from .models_registry import AVAILABLE_MODELS, RECOMMENDED_MODELS, is_valid_model
from .agents.connectors.ticketing import (
    build_ticket_title,
    create_ticket,
    format_ticket_description,
)
from .models import (
    CreateTicketRequest,
    TicketResponse,
)

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


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure unhandled 500s still carry CORS headers so the browser can read the error."""
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {exc}"},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Ensure HTTPException responses also pass through middleware for CORS headers."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
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


@app.post("/agents/trigger_demo", response_model=RunCreated, status_code=201)
def trigger_demo_run(payload: TriggerEvent, background_tasks: BackgroundTasks) -> RunCreated:
    """Kick off the full end-to-end demo pipeline chained on selected scanners.

    Flow:
      1. Create REAL agent_run in public.agent_runs for the selected scanners.
      2. Create DEMO agent_run in demo.agent_runs, tagged with the real run_id.
      3. Background task runs sequentially:
           a. run_master(real_run_id)      — ingestion + normalization + enrichment
           b. run_demo_master(demo_run_id) — samples 1 issue per family from the
              real fetch's -ec2 output, generates 5 remediation packages
      4. Real state → public.*; demo state → demo.*.

    Returns the DEMO run_id — that's what the frontend polls for demo progress.
    Real progress is streamed to the public.agent_trace_events realtime channel
    for the Agents page's Real Pipeline mode.
    """
    import uuid

    sb_pub = supabase_admin()
    sb_demo = supabase_admin_demo()

    # ---- 1. Create the REAL agent_run (same shape as /agents/trigger) ----
    real_insert = (
        sb_pub.table("agent_runs")
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
    if not real_insert.data:
        raise HTTPException(status_code=500, detail="Failed to create real run")
    real_run_id = real_insert.data[0]["run_id"]

    # ---- 2. Create the DEMO agent_run, linked to the real run ----
    demo_event_id = f"demo-{uuid.uuid4().hex[:8]}"
    demo_insert = (
        sb_demo.table("agent_runs")
        .insert(
            {
                "event_id": demo_event_id,
                "triggered_by": "demo",
                "action": "FULL",
                "targets": {
                    "demo": True,
                    "scanners": payload.targets.scanners,
                    "real_run_id": real_run_id,
                },
                "status": "queued",
            }
        )
        .execute()
    )
    if not demo_insert.data:
        raise HTTPException(status_code=500, detail="Failed to create demo run")
    demo_row = demo_insert.data[0]

    # ---- 3. Chain in one background task ----
    def _run_real_then_demo():
        run_master(real_run_id)  # blocks until real pipeline completes
        run_demo_master(demo_row["run_id"], real_run_id=real_run_id)

    background_tasks.add_task(_run_real_then_demo)

    return RunCreated(
        run_id=demo_row["run_id"],
        event_id=demo_row["event_id"],
        status=demo_row["status"],
    )


@app.post("/agents/demo/reset")
def reset_demo_state() -> dict:
    """Wipe demo output tables. Keeps demo.raw_findings (the 5-row seed fixture).

    Called by the frontend before a fresh demo run so every "Run Demo Pipeline"
    click starts from clean state. Ordering: packages → issues → agent_runs
    (agent_trace_events cascades via FK ON DELETE CASCADE).
    """
    sb = supabase_admin_demo()
    pkg_deleted = sb.table("remediation_packages").delete().neq("id", 0).execute()
    issue_deleted = sb.table("issues").delete().neq("id", 0).execute()
    run_deleted = (
        sb.table("agent_runs")
        .delete()
        .neq("run_id", "00000000-0000-0000-0000-000000000000")
        .execute()
    )
    return {
        "packages_deleted": len(pkg_deleted.data or []),
        "issues_deleted": len(issue_deleted.data or []),
        "runs_deleted": len(run_deleted.data or []),
        "raws_preserved": True,
    }


@app.post("/admin/env2/reset")
def reset_env2_baseline() -> dict:
    """Reset the env2 vulnerable-lab EC2 back to its fresh baseline.

    Runs the same 5-step SSM sequence Revanth was doing from the terminal:
      1. terraform destroy (drops current resources)
      2. Wipe S3 state file + DynamoDB lock (clean slate for terraform)
      3. Restore main.tf from main.tf.original + wipe .bak-* files
      4. terraform init + terraform apply (recreates the vulnerable baseline)
      5. checkov re-scan to confirm the 11-failure baseline

    Blocks until the SSM command finishes (~60s on a healthy env2). Returns
    the parsed checkov count + new SG id so the UI can display "env cleaned,
    11 checkov failures, SG sg-xxx" without a second call.
    """
    import base64
    import time
    import boto3

    instance_id = settings.fixer_env2_instance_id
    if not instance_id:
        raise HTTPException(
            status_code=500,
            detail="fixer_env2_instance_id not configured — set it in .env",
        )

    reset_script = """#!/bin/bash
set -e
cd /opt/vuln-labs/cspm-lab
echo "=== STEP 1: terraform destroy ==="
terraform destroy -auto-approve -no-color -input=false 2>&1 | tail -n 5
echo "=== STEP 2: delete S3 state file ==="
aws s3 rm "s3://sisyfix-terraform-state-486655355038/vuln-labs/cspm-lab/vop-vuln-lab-env2/terraform.tfstate" 2>&1 || echo "(state may already be empty)"
echo "=== STEP 3: delete DynamoDB lock entry ==="
aws dynamodb delete-item --table-name sisyfix-terraform-locks --key '{"LockID":{"S":"sisyfix-terraform-state-486655355038/vuln-labs/cspm-lab/vop-vuln-lab-env2/terraform.tfstate-md5"}}' 2>&1 || echo "(lock may not exist)"
echo "=== STEP 4: restore main.tf + wipe .bak files ==="
if [ ! -f main.tf.original ]; then echo "ERROR: main.tf.original not found"; exit 1; fi
cp main.tf.original main.tf
rm -f main.tf.bak-*
rm -rf .terraform .terraform.lock.hcl
echo "=== STEP 5: terraform init + apply ==="
terraform init -backend-config=backend.hcl -input=false -no-color 2>&1 | tail -n 3
terraform apply -auto-approve -no-color -input=false 2>&1 | tail -n 6
echo "=== VERIFY: checkov count ==="
checkov -d . --compact --quiet 2>&1 | grep -E "Passed checks|Failed checks" || echo "checkov output missing"
echo "=== DONE ==="
"""

    b64 = base64.b64encode(reset_script.encode()).decode()
    started = datetime.now(UTC)

    try:
        ssm = boto3.client("ssm", region_name="us-east-1")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=502, detail=f"Failed to create SSM client: {type(e).__name__}: {e}"
        ) from e

    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            TimeoutSeconds=600,
            Parameters={"commands": [f"echo {b64} | base64 -d | bash"]},
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=502, detail=f"SSM send_command failed: {type(e).__name__}: {e}"
        ) from e

    command_id = resp["Command"]["CommandId"]

    # Poll with a 3-minute ceiling. Reset normally finishes in ~60s.
    deadline = time.time() + 180
    invocation = None
    while time.time() < deadline:
        try:
            invocation = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            # SSM hasn't materialised the invocation yet — very early poll
            time.sleep(2)
            continue
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=502,
                detail=f"SSM get_command_invocation failed: {type(e).__name__}: {e}",
            ) from e
        if invocation["Status"] not in ("InProgress", "Pending", "Delayed"):
            break
        time.sleep(4)
    else:
        raise HTTPException(
            status_code=504,
            detail=f"env2 reset exceeded 180s (command_id={command_id})",
        )

    status = invocation["Status"]
    stdout = invocation.get("StandardOutputContent") or ""
    stderr = invocation.get("StandardErrorContent") or ""
    duration_s = int((datetime.now(UTC) - started).total_seconds())

    # Parse the checkov summary + new SG id out of stdout. Non-fatal if missing.
    import re

    checkov_passed = None
    checkov_failed = None
    m = re.search(r"Passed checks:\s*(\d+),\s*Failed checks:\s*(\d+)", stdout)
    if m:
        checkov_passed = int(m.group(1))
        checkov_failed = int(m.group(2))
    new_sg_id = None
    m = re.search(
        r"aws_security_group\.vulnerable_sg:\s*Creation complete[^\[]*\[id=(sg-[a-f0-9]+)\]", stdout
    )
    if m:
        new_sg_id = m.group(1)

    if status != "Success":
        raise HTTPException(
            status_code=500,
            detail={
                "message": f"env2 reset failed with SSM status {status}",
                "command_id": command_id,
                "stderr_tail": stderr[-1500:],
                "stdout_tail": stdout[-1500:],
                "duration_s": duration_s,
            },
        )

    return {
        "status": "success",
        "command_id": command_id,
        "duration_s": duration_s,
        "checkov_passed": checkov_passed,
        "checkov_failed": checkov_failed,
        "new_sg_id": new_sg_id,
        "instance_id": instance_id,
        "stdout_tail": stdout[-800:],
    }


@app.get("/agents/demo/runs")
def list_demo_runs(limit: int = 20) -> dict:
    """List demo pipeline runs — newest first."""
    sb = supabase_admin_demo()
    resp = (
        sb.table("agent_runs")
        .select("run_id, event_id, action, status, started_at, completed_at, summary")
        .order("started_at", desc=True)
        .limit(max(1, min(100, limit)))
        .execute()
    )
    return {"runs": resp.data or []}


@app.get("/agents/demo/runs/{run_id}/traces")
def get_demo_run_traces(run_id: str) -> dict:
    """Trace events for a demo run — ASC by created_at so the UI can replay
    them in order (or subscribe to Realtime once we wire that up)."""
    sb = supabase_admin_demo()
    resp = (
        sb.table("agent_trace_events")
        .select("id, run_id, agent, event_type, message, payload, created_at")
        .eq("run_id", run_id)
        .order("created_at", desc=False)
        .limit(2000)
        .execute()
    )
    return {"traces": resp.data or []}


@app.get("/admin/remediation-packages/demo")
def list_demo_remediation_packages(
    status: str | None = None,
    issue_id: int | None = None,
    limit: int = 50,
) -> dict:
    """List demo remediation packages — same shape as /admin/remediation-packages
    plus `pathways` so the list view can render confidence + validation columns
    without an extra N+1 detail fetch per row. Payload is small (5-50 packages)."""
    sb = supabase_admin_demo()
    q = (
        sb.table("remediation_packages")
        .select(
            "id,issue_id,family,finding,status,approval_required,"
            "recommended_pathway_index,agent_run_id,approved_by,approved_at,"
            "rejected_reason,created_at,updated_at,pathways"
        )
        .order("created_at", desc=True)
        .limit(max(1, min(200, limit)))
    )
    if status:
        q = q.eq("status", status)
    if issue_id is not None:
        q = q.eq("issue_id", issue_id)
    resp = q.execute()
    return {"packages": resp.data or []}


@app.get("/admin/remediation-packages/demo/{pkg_id}")
def get_demo_remediation_package(pkg_id: int) -> dict:
    """Full demo package detail — mirrors the shape of the non-demo endpoint
    so the Remediation drawer can render either without knowing which schema
    the data came from."""
    sb = supabase_admin_demo()
    resp = sb.table("remediation_packages").select("*").eq("id", pkg_id).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"demo remediation_package {pkg_id} not found")
    return resp.data[0]


class CancelRunResponse(BaseModel):
    """Summary returned by the cancel-run endpoint."""

    run_id: str
    previous_status: str
    new_status: str
    scanners_cleaned: list[str]
    issues_deleted: int
    raw_findings_deleted: int


@app.post("/agents/runs/{run_id}/cancel", response_model=CancelRunResponse)
def cancel_run(run_id: str) -> CancelRunResponse:
    """Cancel an in-flight agent run and wipe its scanner's data.

    Effect:
      1. Sets cancellation_requested=true on agent_runs (Master + Sub-Agents
         poll this and bail at their next checkpoint).
      2. Marks the run as 'cancelled'.
      3. DELETES every row in `issues` and `raw_findings` for the scanner(s)
         this run targeted — gives the user a clean slate for retry.
      4. Resets the connection_registry watermark for each scanner so the
         next fetch starts from the beginning.

    Idempotent — safe to call again on an already-cancelled run.
    """
    sb = supabase_admin()

    run = (
        sb.table("agent_runs")
        .select("run_id, status, targets")
        .eq("run_id", run_id)
        .single()
        .execute()
        .data
    )
    if not run:
        raise HTTPException(status_code=404, detail=f"run_id {run_id} not found")

    previous_status = run["status"]
    targets = run.get("targets") or {}
    scanners = targets.get("scanners") or []

    # Flip the flag so any in-flight code paths see it on next poll
    sb.table("agent_runs").update(
        {
            "cancellation_requested": True,
            "status": "cancelled",
            "completed_at": datetime.now(UTC).isoformat(),
            "summary": {"cancelled_by_user": True, "cancelled_at": datetime.now(UTC).isoformat()},
        }
    ).eq("run_id", run_id).execute()

    issues_deleted = 0
    raw_findings_deleted = 0

    for scanner in scanners:
        # Count before delete so we can report numbers
        i_count = (
            sb.table("issues")
            .select("id", count="exact")
            .eq("source", scanner)
            .limit(1)
            .execute()
            .count
            or 0
        )
        r_count = (
            sb.table("raw_findings")
            .select("id", count="exact")
            .eq("source", scanner)
            .limit(1)
            .execute()
            .count
            or 0
        )
        sb.table("issues").delete().eq("source", scanner).execute()
        sb.table("raw_findings").delete().eq("source", scanner).execute()
        sb.table("connection_registry").update({"last_fetched_at": None}).eq(
            "tool", scanner
        ).execute()
        issues_deleted += i_count
        raw_findings_deleted += r_count

    return CancelRunResponse(
        run_id=run_id,
        previous_status=previous_status,
        new_status="cancelled",
        scanners_cleaned=scanners,
        issues_deleted=issues_deleted,
        raw_findings_deleted=raw_findings_deleted,
    )


# ----------------------------------------------------------------------------
# Admin — agent model configuration
# ----------------------------------------------------------------------------

_AGENT_NAMES = ("master", "sub-agent-1", "sub-agent-2")


class AgentModelConfig(BaseModel):
    agent: str
    current_model: str
    recommended_model: str


class AgentsConfigResponse(BaseModel):
    agents: list[AgentModelConfig]
    available_models: dict[str, list[dict[str, str]]]
    # Per-provider readiness — true iff the matching API key is set in .env.
    # The UI uses this to grey out providers the server can't actually call.
    providers_configured: dict[str, bool]


class ModelUpdate(BaseModel):
    model: str = Field(..., min_length=1)


@app.get("/admin/agents/config", response_model=AgentsConfigResponse)
def get_agents_config() -> AgentsConfigResponse:
    """Return the current model selection for each agent plus the curated
    list of models the UI can offer.
    """
    sb = supabase_admin()
    rows = (
        sb.table("prompt_db")
        .select("agent, model")
        .in_("agent", list(_AGENT_NAMES))
        .eq("is_active", True)
        .execute()
        .data
        or []
    )
    by_agent = {r["agent"]: r["model"] for r in rows}

    agents = [
        AgentModelConfig(
            agent=name,
            current_model=by_agent.get(name, RECOMMENDED_MODELS[name]),
            recommended_model=RECOMMENDED_MODELS[name],
        )
        for name in _AGENT_NAMES
    ]

    providers_configured = {
        "openai": bool(settings.openai_api_key),
        "anthropic": bool(settings.anthropic_api_key),
        "google": bool(settings.google_api_key),
    }

    return AgentsConfigResponse(
        agents=agents,
        available_models=AVAILABLE_MODELS,
        providers_configured=providers_configured,
    )


@app.patch("/admin/agents/{agent}/model")
def update_agent_model(agent: str, body: ModelUpdate) -> dict:
    """Update the active prompt_db row's model for a given agent.

    Validates against the curated whitelist so the UI can't push a model
    we haven't confirmed supports function-calling structured output.
    """
    if agent not in _AGENT_NAMES:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent}")
    if not is_valid_model(body.model):
        raise HTTPException(
            status_code=400,
            detail=f"Model '{body.model}' is not in the curated whitelist.",
        )

    sb = supabase_admin()
    update = (
        sb.table("prompt_db")
        .update({"model": body.model})
        .eq("agent", agent)
        .eq("is_active", True)
        .execute()
    )
    if not update.data:
        raise HTTPException(
            status_code=404,
            detail=f"No active prompt row found for agent '{agent}'.",
        )

    return {"agent": agent, "model": body.model}


# ----------------------------------------------------------------------------
# Admin — scanner endpoint configuration
# ----------------------------------------------------------------------------


class ScannerConfig(BaseModel):
    tool: str
    endpoint: str
    protocol: str
    auth_type: str
    enabled: bool
    connector_type: str | None
    last_fetched_at: str | None
    # metadata minus connector_type, surfaced separately for the UI
    metadata: dict


class ScannersResponse(BaseModel):
    scanners: list[ScannerConfig]


class ScannerUpdate(BaseModel):
    """Partial update — any field left None is unchanged."""

    endpoint: str | None = None
    enabled: bool | None = None
    # Sparse metadata merge: keys present here override matching keys in the
    # existing row's metadata jsonb; absent keys stay untouched.
    metadata: dict | None = None


class ScannerCreate(BaseModel):
    """Register a brand-new scanner.

    For tools without a purpose-built connector, leave `connector_type` as
    "user_endpoint" — the generic HTTP-fetch connector will be used.
    """

    tool: str = Field(..., min_length=1, max_length=64)
    endpoint: str = Field(..., min_length=1)
    connector_type: str = "user_endpoint"
    protocol: str = "REST"
    auth_type: str = "custom"
    metadata: dict = Field(default_factory=dict)
    enabled: bool = True


_VALID_CONNECTOR_TYPES = (
    "osv_api",
    "tenable_api",
    "dependabot_api",
    "user_endpoint",
    "file_upload",
)
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB — generous for scanner exports
_VALID_FILE_FORMATS = ("json", "jsonl", "csv", "sarif")


def _ensure_scanner_bucket() -> None:
    """Idempotently create the private `scanner_uploads` bucket on first use.

    Supabase's create_bucket throws if it already exists, so we swallow that
    case and re-raise anything else. Marking the bucket private keeps the
    files out of the public Storage URL space.
    """
    sb = supabase_admin()
    try:
        sb.storage.create_bucket(SCANNER_BUCKET, options={"public": False})
    except Exception as e:
        message = str(e).lower()
        if "already exists" in message or "duplicate" in message:
            return
        raise


def _row_to_scanner_config(row: dict) -> ScannerConfig:
    metadata = row.get("metadata") or {}
    # Redact sensitive fields so secrets never reach the frontend
    safe_metadata = redact_sensitive_fields(metadata)
    return ScannerConfig(
        tool=row["tool"],
        endpoint=row.get("endpoint", ""),
        protocol=row.get("protocol", ""),
        auth_type=row.get("auth_type", ""),
        enabled=bool(row.get("enabled", False)),
        connector_type=metadata.get("connector_type"),
        last_fetched_at=row.get("last_fetched_at"),
        metadata={k: v for k, v in safe_metadata.items() if k != "connector_type"},
    )


@app.get("/admin/scanners", response_model=ScannersResponse)
def list_scanners() -> ScannersResponse:
    """Return every connection_registry row so the UI can render which
    scanners are wired and let users edit their endpoints.
    """
    sb = supabase_admin()
    rows = sb.table("connection_registry").select("*").order("tool").execute().data or []
    return ScannersResponse(scanners=[_row_to_scanner_config(r) for r in rows])


@app.patch("/admin/scanners/{tool}", response_model=ScannerConfig)
def update_scanner(tool: str, body: ScannerUpdate) -> ScannerConfig:
    """Update endpoint / enabled / metadata for one scanner.

    Metadata is shallow-merged with what's already in the row so the UI can
    send only the fields the user actually changed without clobbering keys
    like `connector_type`.
    """
    sb = supabase_admin()

    existing = sb.table("connection_registry").select("*").eq("tool", tool).limit(1).execute().data
    if not existing:
        raise HTTPException(status_code=404, detail=f"Unknown scanner: {tool}")

    current = existing[0]
    update_payload: dict = {}

    if body.endpoint is not None:
        if not body.endpoint.strip():
            raise HTTPException(status_code=400, detail="endpoint cannot be empty")
        update_payload["endpoint"] = body.endpoint.strip()

    if body.enabled is not None:
        update_payload["enabled"] = body.enabled

    if body.metadata is not None:
        current_metadata = current.get("metadata") or {}
        incoming = body.metadata

        # Deep-merge sensitive dict fields (e.g. headers) at the key level.
        # This allows partial header updates: sending {"headers": {"Authorization": "new"}}
        # updates only that key while preserving other encrypted headers.
        # A null value signals deletion: {"headers": {"X-Old-Key": null}} removes that key.
        sensitive = set(get_sensitive_fields())
        merged = {**current_metadata}
        for k, v in incoming.items():
            if k in sensitive and isinstance(v, dict) and isinstance(merged.get(k), dict):
                # Merge at the inner-key level with null-as-delete semantics
                inner = dict(merged[k])
                for ik, iv in v.items():
                    if iv is None:
                        # null signals deletion — remove the key entirely
                        inner.pop(ik, None)
                    else:
                        inner[ik] = iv
                merged[k] = inner
            else:
                merged[k] = v

        # HTTPS enforcement: check the effective endpoint (new or existing)
        effective_endpoint = update_payload.get("endpoint") or current.get("endpoint", "")
        try:
            validate_endpoint_security(effective_endpoint, merged)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

        # Encrypt sensitive fields before persisting
        merged = encrypt_sensitive_fields(merged)
        update_payload["metadata"] = merged

    if not update_payload:
        # No-op — return the current row as-is.
        return _row_to_scanner_config(current)

    update_payload["updated_at"] = datetime.now(UTC).isoformat()

    updated = sb.table("connection_registry").update(update_payload).eq("tool", tool).execute().data
    if not updated:
        raise HTTPException(status_code=500, detail="update returned no rows")

    return _row_to_scanner_config(updated[0])


@app.post("/admin/scanners", response_model=ScannerConfig, status_code=201)
def create_scanner(body: ScannerCreate) -> ScannerConfig:
    """Register a new scanner. Used when the user wires up a tool that
    doesn't have a built-in connector by pasting in a URL on the
    Integrations page.
    """
    if body.connector_type not in _VALID_CONNECTOR_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"connector_type must be one of {list(_VALID_CONNECTOR_TYPES)}; "
                f"got {body.connector_type!r}."
            ),
        )

    sb = supabase_admin()

    existing = (
        sb.table("connection_registry").select("tool").eq("tool", body.tool).limit(1).execute().data
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Scanner '{body.tool}' is already registered. PATCH /admin/scanners/{body.tool} to update.",
        )

    # connector_type lives inside metadata so the dispatcher in
    # connectors/__init__.py can route on it. Caller's metadata wins on
    # collisions, but we set a default to keep the dispatch correct.
    merged_metadata = {"connector_type": body.connector_type, **(body.metadata or {})}
    merged_metadata["connector_type"] = body.connector_type  # ensure it's authoritative

    # HTTPS enforcement: block auth headers against non-HTTPS endpoints
    try:
        validate_endpoint_security(body.endpoint, merged_metadata)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    # Encrypt sensitive fields before persisting
    merged_metadata = encrypt_sensitive_fields(merged_metadata)

    row = {
        "tool": body.tool,
        "protocol": body.protocol,
        "auth_type": body.auth_type,
        "endpoint": body.endpoint,
        "auth_ref": f"user:{body.tool}",
        "metadata": merged_metadata,
        "enabled": body.enabled,
    }

    inserted = sb.table("connection_registry").insert(row).execute().data
    if not inserted:
        raise HTTPException(status_code=500, detail="insert returned no rows")

    return _row_to_scanner_config(inserted[0])


class SecretsStatusResponse(BaseModel):
    """Shows which sensitive fields are configured for a scanner (without values)."""

    tool: str
    encryption_enabled: bool
    fields: dict[str, bool]  # field_name → is_set


@app.get("/admin/scanners/{tool}/secrets-status", response_model=SecretsStatusResponse)
def get_scanner_secrets_status(tool: str) -> SecretsStatusResponse:
    """Return which sensitive fields are set for a scanner, without exposing values.

    Useful for the UI to show lock icons / "configured" badges next to fields.
    """
    from .crypto import get_sensitive_fields

    sb = supabase_admin()
    existing = (
        sb.table("connection_registry").select("metadata").eq("tool", tool).limit(1).execute().data
    )
    if not existing:
        raise HTTPException(status_code=404, detail=f"Unknown scanner: {tool}")

    metadata = existing[0].get("metadata") or {}
    sensitive = get_sensitive_fields()

    fields_status = {}
    for field in sensitive:
        value = metadata.get(field)
        # A field is "set" if it's present and non-empty (encrypted or plaintext)
        fields_status[field] = bool(value)

    return SecretsStatusResponse(
        tool=tool,
        encryption_enabled=is_encryption_enabled(),
        fields=fields_status,
    )


@app.post("/admin/scanners/{tool}/upload", response_model=ScannerConfig)
async def upload_scanner_file(
    tool: str,
    file: UploadFile = File(...),  # noqa: B008 — standard FastAPI pattern for multipart uploads
) -> ScannerConfig:
    """Upload a scanner-export file (JSON/JSONL/CSV/SARIF) for `tool`.

    The file lands in Supabase Storage (bucket: `scanner_uploads`) and the
    pointer + sniffed format are written into connection_registry.metadata.
    Creates the registry row on first upload (so the user can upload before
    the tool is "registered" — same idea as create_scanner but for files).
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename is required")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file is larger than {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
        )

    file_format = sniff_format(file.filename, content)
    if file_format not in _VALID_FILE_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported format '{file_format}'; supported: {list(_VALID_FILE_FORMATS)}",
        )

    _ensure_scanner_bucket()

    # Path layout: <tool>/<unix_ts>_<safe_filename>. Keeps history visible in
    # the Storage browser and avoids collisions on rapid re-uploads.
    safe_name = "".join(c if (c.isalnum() or c in "._-") else "_" for c in file.filename)
    timestamp = int(datetime.now(UTC).timestamp())
    file_pointer = f"{tool}/{timestamp}_{safe_name}"

    sb = supabase_admin()
    # upsert=True so a re-upload to the exact same path (unlikely with the
    # timestamp prefix) doesn't 409 the user — the new file just replaces it.
    sb.storage.from_(SCANNER_BUCKET).upload(
        path=file_pointer,
        file=content,
        file_options={
            "upsert": "true",
            "content-type": file.content_type or "application/octet-stream",
        },
    )

    # Upsert the registry row — create if missing, update its file pointer
    # if it already exists. The connector_type is forced to file_upload so
    # the dispatcher routes correctly.
    existing = sb.table("connection_registry").select("*").eq("tool", tool).limit(1).execute().data
    new_metadata_keys = {
        "connector_type": "file_upload",
        "file_pointer": file_pointer,
        "file_format": file_format,
        "file_filename": file.filename,
        "file_size_bytes": len(content),
        # Drop any stale response_path from a previous shape — the LLM-infer
        # cache should be re-warmed against the new file.
        "response_path": None,
    }

    if existing:
        merged = {**(existing[0].get("metadata") or {}), **new_metadata_keys}
        # None values are stripped — Supabase prefers absence over null in jsonb.
        merged = {k: v for k, v in merged.items() if v is not None}
        updated = (
            sb.table("connection_registry")
            .update(
                {
                    "metadata": merged,
                    "endpoint": "",  # file-based scanners have no URL
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            )
            .eq("tool", tool)
            .execute()
            .data
        )
        if not updated:
            raise HTTPException(status_code=500, detail="update returned no rows")
        return _row_to_scanner_config(updated[0])

    row = {
        "tool": tool,
        "protocol": "FILE",
        "auth_type": "none",
        "endpoint": "",
        "auth_ref": f"file:{tool}",
        "metadata": {k: v for k, v in new_metadata_keys.items() if v is not None},
        "enabled": True,
    }
    inserted = sb.table("connection_registry").insert(row).execute().data
    if not inserted:
        raise HTTPException(status_code=500, detail="insert returned no rows")
    return _row_to_scanner_config(inserted[0])


# ----------------------------------------------------------------------------
# Admin — MITRE CWE catalog refresh
# ----------------------------------------------------------------------------


class MitreRefreshResponse(BaseModel):
    status: str  # "unchanged" | "updated" | "failed"
    cwes_processed: int | None = None
    mitre_version: str | None = None
    sha256: str | None = None
    error_message: str | None = None


@app.post("/admin/mitre/refresh", response_model=MitreRefreshResponse)
def refresh_mitre() -> MitreRefreshResponse:
    """Re-pull the MITRE CWE catalog into the mitre_cwe table.

    Safe to call repeatedly — the SHA-256 hash check makes subsequent runs
    no-ops when MITRE hasn't published a new version. Designed to be hit
    monthly by cron (or pg_cron) and also available as a manual button.
    """
    result = refresh_mitre_cwe()
    if result["status"] == "failed":
        raise HTTPException(status_code=502, detail=result)
    return MitreRefreshResponse(**result)


@app.post("/admin/mitre/refresh-capec", response_model=MitreRefreshResponse)
def refresh_mitre_capec_endpoint() -> MitreRefreshResponse:
    """Re-pull the MITRE CAPEC catalog into the mitre_capec table.

    Same hash-check + idempotency contract as the CWE endpoint. CAPEC has
    a similar release cadence (~3-4 versions per year).
    """
    result = refresh_mitre_capec()
    if result["status"] == "failed":
        raise HTTPException(status_code=502, detail=result)
    return MitreRefreshResponse(**result)


@app.post("/admin/mitre/refresh-attack", response_model=MitreRefreshResponse)
def refresh_mitre_attack_endpoint() -> MitreRefreshResponse:
    """Re-pull the MITRE ATT&CK Enterprise STIX bundle into mitre_attack_techniques.

    Source: github.com/mitre-attack/attack-stix-data. The JSON bundle is large
    (~30 MB) so this call is slower than CWE/CAPEC — typically 20-40 seconds
    on a first run; near-instant on no-op runs thanks to the hash check.
    """
    result = refresh_mitre_attack()
    if result["status"] == "failed":
        raise HTTPException(status_code=502, detail=result)
    return MitreRefreshResponse(**result)


# ----------------------------------------------------------------------------
# Admin — Backfill prioritization-engine scores for existing issues
# ----------------------------------------------------------------------------


class RescoreRequest(BaseModel):
    """Optional body for the rescore endpoint."""

    regenerate_llm: bool = Field(
        default=False,
        description=(
            "When true, also call the LLM with the current sub-agent-2 prompt "
            "to regenerate risk_explanation + remediation_suggestion. Reuses "
            "the issue's already-stored enrichment data (EPSS / KEV / NVD / "
            "MITRE) — does not re-fetch from external sources. Costs ~1 LLM "
            "call per issue."
        ),
    )


class RescoreResponse(BaseModel):
    """Summary returned by the rescore endpoint."""

    issues_processed: int
    issues_updated: int
    llm_regenerated: int
    by_priority: dict[str, int]
    policy_version: str


@app.post("/admin/issues/rescore", response_model=RescoreResponse)
def rescore_issues(body: RescoreRequest | None = None) -> RescoreResponse:
    """Recompute derived_risk / priority / components_summary for ALL issues
    using the current scoring formula (Sub-Agent 2's `_compute_score`).

    Uses the SAME Python helpers Sub-Agent 2 uses during enrichment, so the
    backfill values are byte-identical to what a fresh enrichment would
    produce. Safe to re-run any number of times — the formula is deterministic.

    Optional: pass `{"regenerate_llm": true}` to ALSO re-run the LLM with the
    active sub-agent-2 prompt and overwrite risk_explanation +
    remediation_suggestion. This uses the issue's already-stored enrichment
    (EPSS, KEV, NVD, MITRE chain) — does NOT re-fetch external data. Useful
    when you ship a new prompt (e.g. v1.5) and want the existing 404 issues'
    explanations to reflect the new prompt without running a full scan.
    """
    req = body or RescoreRequest()
    sb = supabase_admin()

    # 1. Load every issue with the columns the formula + LLM payload need.
    issues = (
        sb.table("issues")
        .select(
            "id, severity, cve_id, title, description, cvss_score, "
            "cvss_attack_vector, cvss_attack_complexity, cvss_privileges_required, "
            "cvss_user_interaction, epss_score, epss_percentile, exploit_in_kev, "
            "cwe_id, cwe_name, cwe_likelihood_of_exploit, capec_ids, "
            "attack_technique_ids, attack_tactics, attack_platforms, "
            "package, asset_identity"
        )
        .execute()
        .data
        or []
    )

    # 2. Load assets + build the resolver index.
    asset_rows = sb.table("assets").select("*").execute().data or []
    asset_index = _build_asset_index(asset_rows)

    # 3. If we're regenerating LLM prose, also load the active prompt + MITRE
    #    catalogs (once, batched) so per-issue LLM calls can reconstruct the
    #    rich payload without per-call DB hits.
    prompt_row: dict | None = None
    mitre_cwe_by_id: dict[str, dict] = {}
    mitre_capec_by_id: dict[str, dict] = {}
    mitre_attack_by_id: dict[str, dict] = {}

    if req.regenerate_llm:
        prompt_row = (
            sb.table("prompt_db")
            .select("*")
            .eq("agent", "sub-agent-2")
            .eq("is_active", True)
            .single()
            .execute()
            .data
        )

        # Pull the catalogs we'll need to rebuild mitre_payload per issue.
        cwe_ids_needed = {issue.get("cwe_id") for issue in issues if issue.get("cwe_id")}
        if cwe_ids_needed:
            cwe_rows = (
                sb.table("mitre_cwe").select("*").in_("cwe_id", list(cwe_ids_needed)).execute().data
                or []
            )
            mitre_cwe_by_id = {row["cwe_id"]: row for row in cwe_rows}

        capec_ids_needed: set[str] = set()
        for issue in issues:
            for capec_id in issue.get("capec_ids") or []:
                capec_ids_needed.add(capec_id)
        if capec_ids_needed:
            capec_rows = (
                sb.table("mitre_capec")
                .select("*")
                .in_("capec_id", list(capec_ids_needed))
                .execute()
                .data
                or []
            )
            mitre_capec_by_id = {row["capec_id"]: row for row in capec_rows}

        attack_ids_needed: set[str] = set()
        for issue in issues:
            for tech_id in issue.get("attack_technique_ids") or []:
                attack_ids_needed.add(tech_id)
        if attack_ids_needed:
            attack_rows = (
                sb.table("mitre_attack_techniques")
                .select("*")
                .in_("technique_id", list(attack_ids_needed))
                .execute()
                .data
                or []
            )
            mitre_attack_by_id = {row["technique_id"]: row for row in attack_rows}

    by_priority: dict[str, int] = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    llm_regenerated = 0
    updated = 0

    def _process_one(issue: dict) -> tuple[str, bool]:
        """Score + (optionally) LLM-regenerate one issue. Returns (priority, llm_called)."""
        asset = _resolve_asset(issue, asset_index)
        scoring = _compute_score(issue, asset)

        update_row: dict = {
            "derived_risk": scoring["derived_risk"],
            "priority": scoring["priority"],
            "components_summary": scoring["components_summary"],
            "scoring_policy_version": scoring["scoring_policy_version"],
            "exposure": (asset or {}).get("exposure"),
            "business_criticality": (asset or {}).get("business_criticality"),
            "asset_owner": (asset or {}).get("business_owner"),
        }

        llm_called = False
        if req.regenerate_llm and prompt_row is not None:
            # Reconstruct the LLM payload from stored fields.
            epss_for_llm = {
                "epss_score": issue.get("epss_score"),
                "epss_percentile": issue.get("epss_percentile"),
            }
            nvd_for_llm = {
                "cwe_id": issue.get("cwe_id"),
                "cwe_name": issue.get("cwe_name"),
                "cvss_attack_vector": issue.get("cvss_attack_vector"),
                "cvss_attack_complexity": issue.get("cvss_attack_complexity"),
                "cvss_privileges_required": issue.get("cvss_privileges_required"),
                "cvss_user_interaction": issue.get("cvss_user_interaction"),
            }

            cwe_row = mitre_cwe_by_id.get(issue.get("cwe_id")) if issue.get("cwe_id") else None
            capec_rows = [
                mitre_capec_by_id[cid]
                for cid in (issue.get("capec_ids") or [])
                if cid in mitre_capec_by_id
            ]
            attack_rows = [
                mitre_attack_by_id[tid]
                for tid in (issue.get("attack_technique_ids") or [])
                if tid in mitre_attack_by_id
            ]
            mitre_for_llm = {
                "cwe": cwe_row or {},
                "capec": capec_rows,
                "attack": attack_rows,
            }

            try:
                decision = _llm_decide(
                    run_id="rescore",
                    prompt_row=prompt_row,
                    issue=issue,
                    epss=epss_for_llm,
                    nvd=nvd_for_llm,
                    in_kev=bool(issue.get("exploit_in_kev")),
                    mitre=mitre_for_llm,
                    asset=asset,
                    scoring=scoring,
                )
                update_row["risk_explanation"] = decision.risk_explanation
                update_row["remediation_suggestion"] = decision.remediation_suggestion
                llm_called = True
            except Exception:  # nosec B110 — LLM hiccups shouldn't block the formula update  # noqa: S110
                pass

        sb.table("issues").update(update_row).eq("id", issue["id"]).execute()
        return scoring["priority"], llm_called

    # Parallel processing — Sub-Agent 2 uses the same pattern during enrichment.
    workers = max(1, int(settings.llm_parallel_workers or 10))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_process_one, issue) for issue in issues]
        for future in as_completed(futures):
            priority, llm_called = future.result()
            by_priority[priority] = by_priority.get(priority, 0) + 1
            if llm_called:
                llm_regenerated += 1
            updated += 1

    return RescoreResponse(
        issues_processed=len(issues),
        issues_updated=updated,
        llm_regenerated=llm_regenerated,
        by_priority=by_priority,
        policy_version=SCORING_POLICY_VERSION,
    )


class BackfillCvssResponse(BaseModel):
    """Summary returned by the CVSS backfill endpoint."""

    issues_scanned: int
    vectors_found: int
    scores_filled: int
    versions_filled: int
    skipped_no_raw: int
    skipped_no_vector: int


def _extract_vector_from_raw(raw: dict) -> str | None:
    """Pick the highest-version CVSS vector from a raw scanner payload.

    Walks OSV / NVD / scanner-native shapes via extract_all_vectors_from_raw,
    then prefers V4 > V3.1 > V3.0 > V2. Returns None when no vector is found.
    """
    return pick_best_cvss_vector(extract_all_vectors_from_raw(raw))


@app.post("/admin/issues/backfill_cvss", response_model=BackfillCvssResponse)
def backfill_cvss() -> BackfillCvssResponse:
    """Fill cvss_vector / cvss_score / cvss_version on existing issues by
    re-reading the raw scanner payload from raw_findings.

    Idempotent — only fills NULLs. Existing scores/vectors are never overwritten.
    Safe to run any number of times.

    Use after migration 0026 + the Sub-Agent 1 vector-extraction prompt (v1.2)
    are deployed, to catch up the rows ingested before those landed.
    """
    sb = supabase_admin()

    issues = (
        sb.table("issues")
        .select("id, cvss_score, cvss_version, cvss_vector, raw_finding_id")
        .execute()
        .data
        or []
    )

    raw_ids = [i["raw_finding_id"] for i in issues if i.get("raw_finding_id")]
    raw_by_id: dict[int, dict] = {}
    # Supabase has a URL-length cap on .in_(), so chunk.
    for start in range(0, len(raw_ids), 200):
        chunk = raw_ids[start : start + 200]
        rows = sb.table("raw_findings").select("id, raw").in_("id", chunk).execute().data or []
        for r in rows:
            raw_by_id[r["id"]] = r.get("raw") or {}

    vectors_found = 0
    scores_filled = 0
    versions_filled = 0
    skipped_no_raw = 0
    skipped_no_vector = 0

    for issue in issues:
        raw_id = issue.get("raw_finding_id")
        if not raw_id or raw_id not in raw_by_id:
            skipped_no_raw += 1
            continue

        vec = issue.get("cvss_vector") or _extract_vector_from_raw(raw_by_id[raw_id])
        if not vec:
            skipped_no_vector += 1
            continue

        update_row: dict = {}
        if not issue.get("cvss_vector"):
            update_row["cvss_vector"] = vec
            vectors_found += 1

        # Only compute score/version if missing — never overwrite.
        if issue.get("cvss_score") is None or issue.get("cvss_version") is None:
            score, version = parse_cvss_vector(vec)
            if score is not None and issue.get("cvss_score") is None:
                update_row["cvss_score"] = score
                scores_filled += 1
            if version is not None and issue.get("cvss_version") is None:
                update_row["cvss_version"] = version
                versions_filled += 1

        if update_row:
            sb.table("issues").update(update_row).eq("id", issue["id"]).execute()

    return BackfillCvssResponse(
        issues_scanned=len(issues),
        vectors_found=vectors_found,
        scores_filled=scores_filled,
        versions_filled=versions_filled,
        skipped_no_raw=skipped_no_raw,
        skipped_no_vector=skipped_no_vector,
    )


_CVSS_VERSION_RANK_MAIN = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}


class UpgradeCvssResponse(BaseModel):
    """Summary returned by the CVSS upgrade endpoint."""

    issues_scanned: int
    upgraded: int
    score_corrected: int
    vector_filled: int
    skipped_no_change: int
    skipped_no_raw: int
    skipped_no_vector: int


@app.post("/admin/issues/upgrade_cvss_to_best", response_model=UpgradeCvssResponse)
def upgrade_cvss_to_best() -> UpgradeCvssResponse:
    """Re-evaluate every issue's CVSS against ALL vectors in its raw payload
    and upgrade to the highest version available.

    Differs from /admin/issues/backfill_cvss in one important way: this OVERWRITES
    existing cvss_version + cvss_score when a higher-version vector exists in
    raw_findings. Use this after a prompt or schema bump to retrofit issues
    that were normalized under an older prompt that didn't know about newer
    CVSS versions (e.g. V4).

    Idempotent. Only changes rows where the new pick strictly beats the
    current state.
    """
    sb = supabase_admin()

    issues = (
        sb.table("issues")
        .select("id, cvss_score, cvss_version, cvss_vector, raw_finding_id")
        .execute()
        .data
        or []
    )

    raw_ids = [i["raw_finding_id"] for i in issues if i.get("raw_finding_id")]
    raw_by_id: dict[int, dict] = {}
    for start in range(0, len(raw_ids), 200):
        chunk = raw_ids[start : start + 200]
        rows = sb.table("raw_findings").select("id, raw").in_("id", chunk).execute().data or []
        for r in rows:
            raw_by_id[r["id"]] = r.get("raw") or {}

    upgraded = 0
    score_corrected = 0
    vector_filled = 0
    skipped_no_change = 0
    skipped_no_raw = 0
    skipped_no_vector = 0

    for issue in issues:
        raw_id = issue.get("raw_finding_id")
        if not raw_id or raw_id not in raw_by_id:
            skipped_no_raw += 1
            continue

        candidate_vectors = extract_all_vectors_from_raw(raw_by_id[raw_id])
        if issue.get("cvss_vector"):
            candidate_vectors.append(issue["cvss_vector"])
        best_vector = pick_best_cvss_vector(candidate_vectors)
        if not best_vector:
            skipped_no_vector += 1
            continue

        best_score, best_version = parse_cvss_vector(best_vector)
        if best_version is None:
            skipped_no_vector += 1
            continue

        current_version = issue.get("cvss_version")
        current_score = issue.get("cvss_score")
        current_rank = _CVSS_VERSION_RANK_MAIN.get(current_version or "", 0)
        best_rank = _CVSS_VERSION_RANK_MAIN.get(best_version, 0)

        update_row: dict = {}

        if best_rank > current_rank:
            # Higher version available — overwrite version + score + vector.
            update_row["cvss_vector"] = best_vector
            update_row["cvss_version"] = best_version
            if best_score is not None:
                update_row["cvss_score"] = best_score
            upgraded += 1
        else:
            # Same version. Fill nulls / fix bogus 0.0 score, but don't change version.
            if issue.get("cvss_vector") is None:
                update_row["cvss_vector"] = best_vector
                vector_filled += 1
            # A previous prompt sometimes wrote 0.0 when it couldn't parse — treat
            # that as null and recompute. Real "score = 0.0" doesn't happen for V3+.
            score_is_bogus = current_score is None or (
                isinstance(current_score, (int, float)) and current_score == 0.0
            )
            if score_is_bogus and best_score is not None:
                update_row["cvss_score"] = best_score
                score_corrected += 1

        if not update_row:
            skipped_no_change += 1
            continue

        sb.table("issues").update(update_row).eq("id", issue["id"]).execute()

    return UpgradeCvssResponse(
        issues_scanned=len(issues),
        upgraded=upgraded,
        score_corrected=score_corrected,
        vector_filled=vector_filled,
        skipped_no_change=skipped_no_change,
        skipped_no_raw=skipped_no_raw,
        skipped_no_vector=skipped_no_vector,
    )


class ReenrichMissingResponse(BaseModel):
    """Summary returned by the targeted NVD re-enrichment endpoint."""

    cves_to_lookup: int
    cves_returned_by_nvd: int
    cves_missing_from_nvd: int
    issues_updated: int
    issues_scores_filled: int
    issues_cwe_filled: int


@app.post("/admin/issues/reenrich_missing_cvss", response_model=ReenrichMissingResponse)
def reenrich_missing_cvss() -> ReenrichMissingResponse:
    """Targeted NVD re-fetch for issues that have a CVE id but no CVSS score.

    Runs after the throttle fix (0.66s pace + 5 retries) so CVEs that were
    dropped by NVD 429s in earlier runs get a second chance. Only touches
    rows where cve_id IS NOT NULL AND cvss_score IS NULL — leaves everything
    else alone. Idempotent.

    Use after you ship the throttle fix OR any time NVD's catalog catches up
    to a previously-unscored CVE (e.g. AWAITING_ANALYSIS clears).
    """
    sb = supabase_admin()

    rows = (
        sb.table("issues")
        .select("id, cve_id, cvss_score, cvss_version, cvss_vector, cwe_id")
        .is_("cvss_score", "null")
        .not_.is_("cve_id", "null")
        .execute()
        .data
        or []
    )

    cve_ids = sorted({r["cve_id"] for r in rows if r.get("cve_id")})
    if not cve_ids:
        return ReenrichMissingResponse(
            cves_to_lookup=0,
            cves_returned_by_nvd=0,
            cves_missing_from_nvd=0,
            issues_updated=0,
            issues_scores_filled=0,
            issues_cwe_filled=0,
        )

    nvd_data = _fetch_nvd_data(cve_ids, settings.nvd_api_key or None, run_id="reenrich")

    issues_updated = 0
    issues_scores_filled = 0
    issues_cwe_filled = 0

    for row in rows:
        cve = row.get("cve_id")
        if not cve or cve not in nvd_data:
            continue
        data = nvd_data[cve]
        update_row: dict = {}

        if row.get("cvss_score") is None and data.get("cvss_score") is not None:
            update_row["cvss_score"] = data["cvss_score"]
            issues_scores_filled += 1
        if row.get("cvss_version") is None and data.get("cvss_version") is not None:
            update_row["cvss_version"] = data["cvss_version"]
        if row.get("cvss_vector") is None and data.get("cvss_vector") is not None:
            update_row["cvss_vector"] = data["cvss_vector"]
        if row.get("cwe_id") is None and data.get("cwe_id") is not None:
            update_row["cwe_id"] = data["cwe_id"]
            issues_cwe_filled += 1
        # CVSS v3 sub-vector fields — fill if missing.
        for key in (
            "cvss_attack_vector",
            "cvss_attack_complexity",
            "cvss_privileges_required",
            "cvss_user_interaction",
        ):
            if data.get(key) is not None:
                update_row[key] = data[key]

        if update_row:
            sb.table("issues").update(update_row).eq("id", row["id"]).execute()
            issues_updated += 1

    return ReenrichMissingResponse(
        cves_to_lookup=len(cve_ids),
        cves_returned_by_nvd=len(nvd_data),
        cves_missing_from_nvd=len(cve_ids) - len(nvd_data),
        issues_updated=issues_updated,
        issues_scores_filled=issues_scores_filled,
        issues_cwe_filled=issues_cwe_filled,
    )


class RetryNvdResponse(BaseModel):
    """Summary returned by the NVD retry endpoint."""

    issues_found: int
    cves_to_lookup: int
    cves_from_cache: int
    cves_from_nvd_api: int
    cves_still_missing: int
    issues_rescored: int


@app.post("/admin/issues/retry_failed_nvd", response_model=RetryNvdResponse)
def retry_failed_nvd() -> RetryNvdResponse:
    """Retry NVD enrichment for issues missing NVD-derived fields, then re-score.

    Targets issues that have a CVE id but are missing critical NVD enrichment
    (cvss_attack_vector is NULL — the strongest indicator that NVD data was
    never fetched, since Sub-Agent 1 doesn't produce this field).

    Flow:
      1. Query issues with cve_id present but cvss_attack_vector missing.
      2. Try DynamoDB Intelligence Service first (fast path).
      3. Fall back to NVD API for cache misses (with circuit breaker).
      4. Write-back successful NVD responses to DynamoDB.
      5. For each issue with newly-available NVD data:
         - Resolve the MITRE chain (CWE → CAPEC → ATT&CK).
         - Resolve the asset for business context.
         - Re-run the deterministic scoring formula.
         - Re-run the LLM for updated prose.
         - Update the issue row.

    Idempotent — safe to call multiple times. Issues already enriched are
    skipped by the WHERE filter.
    """
    sb = supabase_admin()

    # 1. Find issues needing NVD data
    rows = (
        sb.table("issues")
        .select(
            "id, cve_id, severity, title, description, cvss_score, cvss_version, "
            "cvss_vector, cvss_attack_vector, cwe_id, epss_score, epss_percentile, "
            "exploit_in_kev, package, asset_identity"
        )
        .is_("cvss_attack_vector", "null")
        .not_.is_("cve_id", "null")
        .execute()
        .data
        or []
    )

    if not rows:
        return RetryNvdResponse(
            issues_found=0,
            cves_to_lookup=0,
            cves_from_cache=0,
            cves_from_nvd_api=0,
            cves_still_missing=0,
            issues_rescored=0,
        )

    cve_ids = sorted({r["cve_id"] for r in rows if r.get("cve_id")})

    # 2. Try DynamoDB first
    nvd_data: dict[str, dict] = {}
    if settings.intelligence_enabled:
        nvd_data = _fetch_nvd_data_from_intelligence(cve_ids, run_id="retry-nvd")

    cves_from_cache = len(nvd_data)

    # 3. NVD API fallback for misses (circuit breaker protects against prolonged outage)
    missed_cves = [cve for cve in cve_ids if cve not in nvd_data]
    cves_from_nvd_api = 0
    if missed_cves:
        nvd_key = settings.nvd_api_key or None
        raw_nvd_responses: list[dict] = []
        fallback_data = _fetch_nvd_data(
            missed_cves,
            nvd_key,
            run_id="retry-nvd",
            collect_raw=raw_nvd_responses,
        )
        nvd_data.update(fallback_data)
        cves_from_nvd_api = len(fallback_data)

        # Write-back to DynamoDB for future cache hits
        if raw_nvd_responses:
            _write_back_nvd_to_dynamo(raw_nvd_responses, run_id="retry-nvd")

    cves_still_missing = len(cve_ids) - len(nvd_data)

    # 4. Load MITRE catalogs for newly-resolved CWEs
    new_cwe_ids = {nvd_data[cve].get("cwe_id") for cve in nvd_data if nvd_data[cve].get("cwe_id")}
    mitre_cwe_by_id: dict[str, dict] = {}
    mitre_capec_by_id: dict[str, dict] = {}
    mitre_attack_by_id: dict[str, dict] = {}

    if new_cwe_ids:
        cwe_rows = (
            sb.table("mitre_cwe")
            .select("cwe_id,name,description,likelihood_of_exploit,mitigations,related_capec")
            .in_("cwe_id", list(new_cwe_ids))
            .execute()
            .data
            or []
        )
        mitre_cwe_by_id = {row["cwe_id"]: row for row in cwe_rows}

        capec_ids_needed: set[str] = set()
        for cwe_row in mitre_cwe_by_id.values():
            for capec_id in cwe_row.get("related_capec") or []:
                capec_ids_needed.add(capec_id)

        if capec_ids_needed:
            capec_rows = (
                sb.table("mitre_capec")
                .select(
                    "capec_id,name,likelihood_of_attack,typical_severity,related_attack_techniques"
                )
                .in_("capec_id", list(capec_ids_needed))
                .execute()
                .data
                or []
            )
            mitre_capec_by_id = {row["capec_id"]: row for row in capec_rows}

        attack_ids_needed: set[str] = set()
        for capec_row in mitre_capec_by_id.values():
            for tech_id in capec_row.get("related_attack_techniques") or []:
                attack_ids_needed.add(tech_id)

        if attack_ids_needed:
            attack_rows = (
                sb.table("mitre_attack_techniques")
                .select("technique_id,name,tactics,platforms")
                .in_("technique_id", list(attack_ids_needed))
                .execute()
                .data
                or []
            )
            mitre_attack_by_id = {row["technique_id"]: row for row in attack_rows}

    # 5. Load assets + active prompt for re-scoring + LLM
    asset_rows = sb.table("assets").select("*").execute().data or []
    asset_index = _build_asset_index(asset_rows)

    prompt_row = (
        sb.table("prompt_db")
        .select("*")
        .eq("agent", "sub-agent-2")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    # 6. Re-score each affected issue
    issues_rescored = 0
    workers = max(1, int(settings.llm_parallel_workers or 5))

    def _rescore_one(issue: dict) -> bool:
        cve = issue.get("cve_id")
        if not cve or cve not in nvd_data:
            return False

        nvd = nvd_data[cve]
        cwe_id = nvd.get("cwe_id") or issue.get("cwe_id")

        # Build MITRE chain
        cwe_row = mitre_cwe_by_id.get(cwe_id) if cwe_id else None
        capec_rows_local: list[dict] = []
        attack_rows_local: list[dict] = []
        if cwe_row:
            for capec_id in cwe_row.get("related_capec") or []:
                row = mitre_capec_by_id.get(capec_id)
                if row:
                    capec_rows_local.append(row)
            for capec_row in capec_rows_local:
                for tech_id in capec_row.get("related_attack_techniques") or []:
                    row = mitre_attack_by_id.get(tech_id)
                    if row:
                        attack_rows_local.append(row)

        cwe_likelihood = (cwe_row or {}).get("likelihood_of_exploit")
        attack_tactics_list = sorted(
            {t for ar in attack_rows_local for t in (ar.get("tactics") or [])}
        )

        # Resolve asset
        asset = _resolve_asset(issue, asset_index)

        # Build scoring snapshot
        issue_for_scoring = {
            **issue,
            "epss_score": issue.get("epss_score"),
            "exploit_in_kev": issue.get("exploit_in_kev"),
            "cvss_score": nvd.get("cvss_score") or issue.get("cvss_score"),
            "cvss_attack_vector": nvd.get("cvss_attack_vector"),
            "cwe_likelihood_of_exploit": cwe_likelihood,
            "attack_tactics": attack_tactics_list,
        }
        scoring = _compute_score(issue_for_scoring, asset)

        # LLM prose
        mitre_payload = {
            "cwe": cwe_row or {},
            "capec": capec_rows_local,
            "attack": attack_rows_local,
        }
        epss_for_llm = {
            "epss_score": issue.get("epss_score"),
            "epss_percentile": issue.get("epss_percentile"),
        }

        update_row: dict = {
            "cwe_id": cwe_id,
            "cwe_name": (cwe_row or {}).get("name"),
            "cvss_score": nvd.get("cvss_score") or issue.get("cvss_score"),
            "cvss_version": nvd.get("cvss_version") or issue.get("cvss_version"),
            "cvss_vector": nvd.get("cvss_vector") or issue.get("cvss_vector"),
            "cvss_attack_vector": nvd.get("cvss_attack_vector"),
            "cvss_attack_complexity": nvd.get("cvss_attack_complexity"),
            "cvss_privileges_required": nvd.get("cvss_privileges_required"),
            "cvss_user_interaction": nvd.get("cvss_user_interaction"),
            "cwe_likelihood_of_exploit": cwe_likelihood,
            "attack_tactics": attack_tactics_list,
            "attack_technique_ids": sorted(
                {ar["technique_id"] for ar in attack_rows_local if ar.get("technique_id")}
            ),
            "derived_risk": scoring["derived_risk"],
            "priority": scoring["priority"],
            "components_summary": scoring["components_summary"],
            "scoring_policy_version": scoring["scoring_policy_version"],
            "exposure": (asset or {}).get("exposure"),
            "business_criticality": (asset or {}).get("business_criticality"),
            "asset_owner": (asset or {}).get("business_owner"),
        }

        # Re-generate LLM prose with full context
        try:
            decision = _llm_decide(
                run_id="retry-nvd",
                prompt_row=prompt_row,
                issue=issue,
                epss=epss_for_llm,
                nvd=nvd,
                in_kev=bool(issue.get("exploit_in_kev")),
                mitre=mitre_payload,
                asset=asset,
                scoring=scoring,
            )
            update_row["risk_explanation"] = decision.risk_explanation
            update_row["remediation_suggestion"] = decision.remediation_suggestion
        except Exception:  # nosec B110 — LLM failure shouldn't block the NVD + score update  # noqa: S110
            pass

        update_row["enriched_at"] = datetime.now(UTC).isoformat()
        sb.table("issues").update(update_row).eq("id", issue["id"]).execute()
        return True

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_rescore_one, issue) for issue in rows]
        for future in as_completed(futures):
            try:
                if future.result():
                    issues_rescored += 1
            except Exception:  # nosec B110 — per-issue failures are non-fatal  # noqa: S110
                pass

    return RetryNvdResponse(
        issues_found=len(rows),
        cves_to_lookup=len(cve_ids),
        cves_from_cache=cves_from_cache,
        cves_from_nvd_api=cves_from_nvd_api,
        cves_still_missing=cves_still_missing,
        issues_rescored=issues_rescored,
    )


# =============================================================================
# Remediation Packages — Phase-1 §5 / §9 (Day 5)
# =============================================================================


class GeneratePackagesRequest(BaseModel):
    issue_ids: list[int] = Field(..., min_length=1, max_length=20)


class PackageGeneratedItem(BaseModel):
    issue_id: int
    package_id: int | None = None
    status: str  # 'created' | 'failed'
    error: str | None = None


class GeneratePackagesResponse(BaseModel):
    run_id: str
    packages: list[PackageGeneratedItem]


class RejectPackageRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)
    rejected_by: str = Field("system", max_length=120)


class ApprovePackageRequest(BaseModel):
    approved_by: str = Field("system", max_length=120)


def _create_planner_run(sb) -> str:
    """Create one agent_runs row for a /generate batch so trace events have a
    valid run_id and the resulting packages can be grouped under one run."""
    import uuid as _uuid
    import time as _time

    run_id = str(_uuid.uuid4())
    sb.table("agent_runs").insert(
        {
            "run_id": run_id,
            "event_id": f"remediation-planner-api-{int(_time.time() * 1000)}",
            "triggered_by": "remediation_planner_api",
            "action": "FULL",
            "targets": {"scanners": [], "scope": ["remediation_packages_generate"]},
            "status": "running",
        }
    ).execute()
    return run_id


def _complete_planner_run(sb, run_id: str, *, success_count: int, total: int) -> None:
    sb.table("agent_runs").update(
        {
            "status": "completed" if success_count == total else "failed",
            "completed_at": datetime.now(UTC).isoformat(),
            "summary": {
                "agent": "sub-agent-3",
                "packages_generated": success_count,
                "requested": total,
            },
        }
    ).eq("run_id", run_id).execute()


@app.post("/admin/remediation-packages/generate", response_model=GeneratePackagesResponse)
def generate_remediation_packages(body: GeneratePackagesRequest) -> GeneratePackagesResponse:
    """Generate + persist a Remediation Package for each issue_id.

    Sequential (one LLM call per issue). For Phase-1's 5 demo issues this
    takes ~75-100s total; acceptable since this is a one-off demo flow.
    """
    sb = supabase_admin()
    run_id = _create_planner_run(sb)
    results: list[PackageGeneratedItem] = []

    for issue_id in body.issue_ids:
        resp = (
            sb.table("issues")
            .select(
                "id,source,severity,priority,cve_id,cwe_id,title,description,"
                "asset_identity,package,runtime_hostname,runtime_ipv4,"
                "runtime_os_family,runtime_purl"
            )
            .eq("id", issue_id)
            .limit(1)
            .execute()
        )
        if not resp.data:
            results.append(
                PackageGeneratedItem(issue_id=issue_id, status="failed", error="issue not found")
            )
            continue
        try:
            pkg = plan_remediation(resp.data[0], run_id=run_id, sb=sb)
            pkg_id = persist_package(pkg, run_id=run_id, sb=sb)
            results.append(
                PackageGeneratedItem(issue_id=issue_id, package_id=pkg_id, status="created")
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                PackageGeneratedItem(
                    issue_id=issue_id,
                    status="failed",
                    error=f"{type(exc).__name__}: {str(exc)[:200]}",
                )
            )

    successes = sum(1 for r in results if r.status == "created")
    _complete_planner_run(sb, run_id, success_count=successes, total=len(body.issue_ids))
    return GeneratePackagesResponse(run_id=run_id, packages=results)


@app.get("/admin/remediation-packages")
def list_remediation_packages(
    status: str | None = None,
    issue_id: int | None = None,
    limit: int = 50,
) -> dict:
    """List packages — paginated, filterable by status + issue_id."""
    sb = supabase_admin()
    q = (
        sb.table("remediation_packages")
        .select(
            "id,issue_id,family,finding,status,approval_required,"
            "recommended_pathway_index,agent_run_id,approved_by,approved_at,"
            "rejected_reason,created_at,updated_at"
        )
        .order("created_at", desc=True)
        .limit(max(1, min(200, limit)))
    )
    if status:
        q = q.eq("status", status)
    if issue_id is not None:
        q = q.eq("issue_id", issue_id)
    resp = q.execute()
    return {"packages": resp.data or []}


@app.get("/admin/remediation-packages/{pkg_id}")
def get_remediation_package(pkg_id: int) -> dict:
    """Full package detail — includes the pathways jsonb (with confidence
    breakdowns, validation_metadata, rollback_plan, etc.)."""
    sb = supabase_admin()
    resp = sb.table("remediation_packages").select("*").eq("id", pkg_id).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"remediation_package {pkg_id} not found")
    return resp.data[0]


@app.post("/admin/remediation-packages/{pkg_id}/approve")
def approve_remediation_package(pkg_id: int, body: ApprovePackageRequest | None = None) -> dict:
    """Transition the package: awaiting_approval → approved → ready_for_execution.

    Phase-1 collapses approval into a single step (single_approver default).
    multi_stage approvals require multiple POSTs; not enforced server-side
    in Phase-1 — the UI controls it.
    """
    sb = supabase_admin()
    resp = sb.table("remediation_packages").select("status").eq("id", pkg_id).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"remediation_package {pkg_id} not found")
    current = resp.data[0]["status"]
    if current in ("approved", "ready_for_execution"):
        return {"id": pkg_id, "status": current, "message": "already approved"}
    if current == "rejected":
        raise HTTPException(status_code=409, detail="package was rejected; cannot approve")

    approved_by = body.approved_by if body else "system"
    sb.table("remediation_packages").update(
        {
            "status": "ready_for_execution",
            "approved_by": approved_by,
            "approved_at": datetime.now(UTC).isoformat(),
            "rejected_reason": None,
        }
    ).eq("id", pkg_id).execute()

    # --- Auto-create ServiceNow ticket on approval (if enabled) ---
    ticket_info: dict | None = None
    if settings.ticketing_auto_create_on_approve:
        try:
            ticket_resp = create_ticket_endpoint(
                CreateTicketRequest(remediation_package_id=pkg_id)
            )
            ticket_info = {
                "ticket_id": ticket_resp.id,
                "external_ticket_id": ticket_resp.external_ticket_id,
                "external_ticket_url": ticket_resp.external_ticket_url,
                "status": ticket_resp.status,
            }
        except Exception:  # noqa: BLE001
            # Ticket creation failure should NOT block approval
            ticket_info = {"status": "failed", "error": "auto-creation failed (see logs)"}

    result = {"id": pkg_id, "status": "ready_for_execution", "approved_by": approved_by}
    if ticket_info:
        result["ticket"] = ticket_info
    return result


@app.post("/admin/remediation-packages/{pkg_id}/reject")
def reject_remediation_package(pkg_id: int, body: RejectPackageRequest) -> dict:
    """Transition the package: awaiting_approval → rejected. Final state.

    To re-attempt, generate a new package for the same issue (will create a
    new row — packages are append-only history).
    """
    sb = supabase_admin()
    resp = sb.table("remediation_packages").select("status").eq("id", pkg_id).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"remediation_package {pkg_id} not found")
    current = resp.data[0]["status"]
    if current in ("approved", "ready_for_execution"):
        raise HTTPException(status_code=409, detail=f"package is already {current}; cannot reject")
    if current == "rejected":
        return {"id": pkg_id, "status": "rejected", "message": "already rejected"}

    sb.table("remediation_packages").update(
        {
            "status": "rejected",
            "rejected_reason": body.reason,
            "approved_by": body.rejected_by,
            "approved_at": datetime.now(UTC).isoformat(),
        }
    ).eq("id", pkg_id).execute()
    return {
        "id": pkg_id,
        "status": "rejected",
        "reason": body.reason,
        "rejected_by": body.rejected_by,
    }


@app.post("/admin/remediation-packages/{pkg_id}/fix", status_code=202)
def fix_remediation_package(pkg_id: int, background_tasks: BackgroundTasks) -> dict:
    """Dispatch Sub-Agent 4 (the Fixer) against this package.

    Runs in the background — returns 202 immediately with the new fix_run id.
    Poll `/admin/fix-runs/{id}` (Phase-2 endpoint) or watch the trace stream
    for progress.

    Requires:
      - package.status = 'ready_for_execution' (previously approved)
      - settings.fixer_env2_instance_id set (env2 provisioned)

    Real pipeline is manual-trigger only — the demo pipeline auto-chains
    via master_demo's fix node. Production intentionally requires an
    explicit human click before touching env2.
    """
    sb = supabase_admin()
    resp = sb.table("remediation_packages").select("status").eq("id", pkg_id).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"remediation_package {pkg_id} not found")
    current = resp.data[0]["status"]
    if current != "ready_for_execution":
        raise HTTPException(
            status_code=409,
            detail=(
                f"package status={current!r} — must be 'ready_for_execution' "
                "(approve it first via /approve)"
            ),
        )

    from .config import settings  # noqa: PLC0415

    if not settings.fixer_env2_instance_id:
        raise HTTPException(
            status_code=503,
            detail=(
                "FIXER_ENV2_INSTANCE_ID not configured. Provision env2 and set "
                "the instance id via env before enabling the /fix endpoint."
            ),
        )

    # Fresh agent_run_id for this fix — traces stream under this id.
    import uuid  # noqa: PLC0415

    fix_run_uuid = str(uuid.uuid4())
    sb.table("agent_runs").insert(
        {
            "run_id": fix_run_uuid,
            "event_id": f"fix-package-{pkg_id}",
            "persona": "sub-agent-4",
            "status": "pending",
            "started_at": datetime.now(UTC).isoformat(),
        }
    ).execute()

    def _dispatch() -> None:
        from .agents.fixer import run_fixer  # noqa: PLC0415
        from .agents.trace import emit_trace  # noqa: PLC0415

        try:
            run_fixer(
                pkg_id,
                agent_run_id=fix_run_uuid,
                sb=sb,
                emit_fn=emit_trace,
                environment="sandbox",
            )
        except Exception as exc:  # noqa: BLE001
            emit_trace(
                fix_run_uuid,
                "sub-agent-4",
                "ERROR",
                f"Fixer dispatch failed: {type(exc).__name__}: {str(exc)[:300]}",
            )

    background_tasks.add_task(_dispatch)
    return {"agent_run_id": fix_run_uuid, "package_id": pkg_id, "status": "dispatched"}


# =============================================================================
# Ticketing — ServiceNow integration endpoints
# =============================================================================


@app.post("/admin/tickets/create", response_model=TicketResponse, status_code=201)
def create_ticket_endpoint(body: CreateTicketRequest) -> TicketResponse:
    """Create a ticket in ServiceNow (or another configured provider) for a
    remediation package.

    Flow:
      1. Load the remediation package + associated issue
      2. Resolve the ticketing connection from connection_registry
      3. Format the ticket content from the package
      4. Call the provider API (ServiceNow Table API)
      5. Persist the ticket record in the tickets table
      6. Return the ticket with external references
    """
    sb = supabase_admin()

    # 1. Load the remediation package
    pkg_resp = (
        sb.table("remediation_packages")
        .select("*")
        .eq("id", body.remediation_package_id)
        .limit(1)
        .execute()
    )
    if not pkg_resp.data:
        raise HTTPException(
            status_code=404,
            detail=f"Remediation package {body.remediation_package_id} not found",
        )
    package = pkg_resp.data[0]

    # Load the associated issue for context
    issue: dict | None = None
    if package.get("issue_id"):
        issue_resp = (
            sb.table("issues")
            .select("id,source,severity,priority,cve_id,cwe_id,title,description")
            .eq("id", package["issue_id"])
            .limit(1)
            .execute()
        )
        if issue_resp.data:
            issue = issue_resp.data[0]

    # 2. Resolve ticketing connection from connection_registry
    tool_name = body.connection_tool or "servicenow-ticket"
    conn_resp = (
        sb.table("connection_registry")
        .select("*")
        .eq("tool", tool_name)
        .eq("enabled", True)
        .limit(1)
        .execute()
    )
    if not conn_resp.data:
        raise HTTPException(
            status_code=404,
            detail=f"No enabled ticketing connection '{tool_name}' found in connection_registry. "
            "Run migration 0037 or register via POST /admin/scanners.",
        )
    connection = conn_resp.data[0]
    metadata = connection.get("metadata") or {}
    provider = metadata.get("connector_type", "servicenow_ticket").replace("_ticket", "")

    # 3. Format ticket content
    title = body.title_override or build_ticket_title(package, issue)
    description = body.description_override or format_ticket_description(
        package=package, issue=issue
    )
    severity = (issue or {}).get("severity", "Medium")
    labels = [
        f"family:{package.get('family', 'unknown')}",
        f"package_id:{package['id']}",
    ]
    if issue and issue.get("cve_id"):
        labels.append(issue["cve_id"])

    # Build config from connection_registry + env vars
    connection_config = {
        "instance_url": connection.get("endpoint") or "",
        **metadata,
    }

    # 4. Call the provider API
    result = create_ticket(
        provider=provider,
        connection_config=connection_config,
        title=title,
        description=description,
        severity=severity,
        labels=labels,
        extra_fields=body.extra_fields,
    )

    # 5. Persist the ticket record
    ticket_row = {
        "remediation_package_id": body.remediation_package_id,
        "connection_tool": tool_name,
        "provider": provider,
        "status": "created" if result.success else "failed",
        "title": title,
        "description": description[:4000],
        "priority": _severity_to_ticket_priority(severity),
        "labels": labels,
        "external_ticket_id": result.external_ticket_id if result.success else None,
        "external_ticket_url": result.external_ticket_url if result.success else None,
        "error_message": result.error if not result.success else None,
    }
    insert_resp = sb.table("tickets").insert(ticket_row).execute()
    if not insert_resp.data:
        raise HTTPException(status_code=500, detail="Failed to insert ticket record")
    ticket = insert_resp.data[0]

    return TicketResponse(**ticket)


@app.post(
    "/admin/remediation-packages/{pkg_id}/create-ticket",
    response_model=TicketResponse,
    status_code=201,
)
def create_ticket_for_package(pkg_id: int) -> TicketResponse:
    """Convenience endpoint — create a ticket for a specific package using
    the default ServiceNow connection. Equivalent to POST /admin/tickets/create
    with just the package ID."""
    return create_ticket_endpoint(CreateTicketRequest(remediation_package_id=pkg_id))


@app.get("/admin/tickets")
def list_tickets(
    status: str | None = None,
    remediation_package_id: int | None = None,
    limit: int = 50,
) -> dict:
    """List tickets — filterable by status and/or package ID."""
    sb = supabase_admin()
    q = (
        sb.table("tickets")
        .select("*")
        .order("created_at", desc=True)
        .limit(max(1, min(200, limit)))
    )
    if status:
        q = q.eq("status", status)
    if remediation_package_id is not None:
        q = q.eq("remediation_package_id", remediation_package_id)
    resp = q.execute()
    return {"tickets": resp.data or []}


@app.get("/admin/tickets/{ticket_id}")
def get_ticket(ticket_id: int) -> dict:
    """Get a single ticket by ID."""
    sb = supabase_admin()
    resp = sb.table("tickets").select("*").eq("id", ticket_id).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
    return resp.data[0]


# ---------------------------------------------------------------------------
# Ticketing helpers
# ---------------------------------------------------------------------------


def _severity_to_ticket_priority(severity: str) -> str:
    """Map issue severity to a ticket priority label."""
    mapping = {
        "Critical": "P1",
        "High": "P2",
        "Medium": "P3",
        "Low": "P4",
        "Info": "P5",
    }
    return mapping.get(severity, "P3")
