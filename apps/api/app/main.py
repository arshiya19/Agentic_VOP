from datetime import UTC, datetime, timedelta

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from concurrent.futures import ThreadPoolExecutor, as_completed

from .agents.connectors.file_upload import SCANNER_BUCKET, sniff_format
from .agents.master import run_master
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
    _llm_decide,
    _resolve_asset,
)
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
