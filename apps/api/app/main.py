from datetime import UTC, datetime, timedelta

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .agents.connectors.file_upload import SCANNER_BUCKET, sniff_format
from .agents.master import run_master
from .config import settings
from .db import supabase_admin
from .mitre_refresh import refresh_mitre_attack, refresh_mitre_capec, refresh_mitre_cwe
from .models import RunCreated, TriggerEvent
from .models_registry import AVAILABLE_MODELS, RECOMMENDED_MODELS, is_valid_model

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


_VALID_CONNECTOR_TYPES = ("osv_api", "tenable_api", "user_endpoint", "file_upload")
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
    return ScannerConfig(
        tool=row["tool"],
        endpoint=row.get("endpoint", ""),
        protocol=row.get("protocol", ""),
        auth_type=row.get("auth_type", ""),
        enabled=bool(row.get("enabled", False)),
        connector_type=metadata.get("connector_type"),
        last_fetched_at=row.get("last_fetched_at"),
        metadata={k: v for k, v in metadata.items() if k != "connector_type"},
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
        merged = {**(current.get("metadata") or {}), **body.metadata}
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
