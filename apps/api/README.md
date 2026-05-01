# Agentic_VOP API — backend handoff guide

This is the backend of Agentic_VOP. It receives user triggers from the frontend,
runs a multi-agent vulnerability pipeline, and persists everything to Supabase.

This README is written assuming **you've never seen this code before** — it
walks every file, what it does, why it exists, and how the pieces fit together.

> Big picture / repo layout: [`../../README.md`](../../README.md)
> Frontend: [`../web/README.md`](../web/README.md)
> Database schema: [`../../supabase/README.md`](../../supabase/README.md)

---

## 1. The 60-second pitch

When a user clicks **Fetch findings** on the Integrations page:

1. Frontend POSTs to **`/agents/trigger`** here.
2. The API persists a row in `agent_runs`, kicks off the **Master Agent** as
   a FastAPI background task, and returns immediately. Endpoint never blocks.
3. **Master** loops over the requested scanners, dispatching to **Sub-Agent 1**
   per scanner. After all FETCHes finish, it dispatches to **Sub-Agent 2**.
4. **Sub-Agent 1 (Smart Connector)** fetches raw rows from the scanner, persists
   them verbatim into `raw_findings`, then for each row calls the LLM to produce
   a canonical Issue and inserts it into `issues`.
5. **Sub-Agent 2 (Enrichment Specialist)** queries EPSS, CISA KEV, and NVD for
   every CVE, then for each Issue calls the LLM to compute a `derived_risk`
   score, written explanation, and remediation suggestion. Updates `issues`.
6. Throughout, every step writes a row to `agent_trace_events`. Supabase Realtime
   pushes those rows to the frontend so the user watches the run live.

---

## 2. Architectural decisions (the "why")

A few non-obvious calls baked into this codebase. Worth knowing before reading the code.

### Agents reason, code transports
Every agent is structured as **prompt + LLM + tools**. The LLM does fuzzy
work (mapping fields, scoring risk, writing explanations). Plain Python code
does deterministic work (HTTP requests, DB writes, hash computation). We never
ask the LLM to do things code can do reliably.

### Function calling for all structured output
When we call the LLM and need a structured response (a canonical Issue, a risk
decision), we use the function-calling feature with a Pydantic-derived JSON schema.
**The LLM API enforces the schema at the API level** — the response is guaranteed
to match. We never do `json.loads()` on LLM text. This eliminates a whole
category of escape/format bugs.

### Postgres LISTEN/NOTIFY + Supabase Realtime instead of Redis
The reference architecture proposes Redis pub/sub. We use Postgres + Supabase
Realtime for the same semantics with one fewer database to manage.

### Generic prompts, scanner knowledge in the database
Sub-Agent 1 has **one** prompt for all scanners. Per-scanner translation rules
live in the `schema_mapping` table and are loaded at runtime alongside the
prompt. **Adding a new scanner is a SQL `INSERT`, not a code or prompt change.**

### Append-only `issues`, no dedup
Same vulnerability seen twice = two rows. Each row carries `agent_run_id` so
queries can filter to "the latest run." No fingerprint UNIQUE constraint.
Simpler, audit-friendly, and matches how scanner products actually behave.

### Watermark on connectors
Each connector_registry row has a `last_fetched_at` timestamp. Sub-Agent 1
filters fetches to "only what's new since." First run pulls everything;
subsequent runs only pull deltas. Production-grade incremental fetch.

### Idempotency on `event_id`
Trigger payload includes a unique `event_id`. The first call inserts a run;
the second call with the same `event_id` returns the existing run without
re-triggering. Safe to retry from any client.

### Parallel sub-agent execution
Sub-Agent 1 and Sub-Agent 2 each run their per-row LLM calls in a
`ThreadPoolExecutor` of `LLM_PARALLEL_WORKERS` size (default 5). Per-row
errors are caught individually so one bad row never poisons the whole run.
At default Tier-1 OpenAI rate limits, 5 workers gives ~150K TPM peak —
under the 200K limit. Bump higher on Tier 2+.

### Rate-limit absorption
The OpenAI client is configured with `max_retries=10`, so transient 429s
(TPM bursts) are retried with exponential backoff inside the SDK. On top
of that, each per-row LLM call is wrapped in a single in-code retry to
ride out occasional malformed-JSON glitches. Combined effect: ~99.5%+
row success rate without manual intervention.

### LLM-driven Master
Master Agent loads its own prompt (`master@v1.0`) and produces a structured
`MasterPlan` via OpenAI function calling on every run. Today the plan is
the same two steps (FETCH + ENRICH), but the structure is ready for
dynamic routing: skip ENRICH on empty FETCH, prioritize critical scanners
first, fan out by scanner type, etc. — all controllable by editing the
prompt in `prompt_db`, no code change.

---

## 3. Folder layout

```
apps/api/
├── pyproject.toml            # uv-managed Python deps
├── uv.lock                   # locked versions (committed)
├── .env                      # secrets (gitignored)
├── .env.example              # template
└── app/
    ├── __init__.py           # empty marker — makes `app` a package
    ├── main.py               # FastAPI app + the /agents/trigger endpoint
    ├── config.py             # env-var loading via pydantic-settings
    ├── db.py                 # Supabase admin client factory
    ├── models.py             # all Pydantic models used everywhere
    └── agents/
        ├── __init__.py
        ├── trace.py          # emit_trace() — writes one row to agent_trace_events
        ├── llm.py            # OpenAI SDK client (lazy singleton)
        ├── master.py         # Master Agent orchestration
        ├── sub_agent_1.py    # Sub-Agent 1: Smart Connector
        ├── sub_agent_2.py    # Sub-Agent 2: Enrichment Specialist
        └── connectors/
            ├── __init__.py   # dispatcher: routes by metadata.connector_type
            ├── osv_api.py    # connector for OSV.dev
            └── tenable_api.py # connector for local Nessus (kept for reference)
```

---

## 4. File-by-file walkthrough

### `pyproject.toml`
Standard uv-managed Python project file. Locks Python ≥ 3.11, declares deps:
- `fastapi` + `uvicorn` (web framework + dev server)
- `pydantic` + `pydantic-settings` (typed models + env loading)
- `supabase` (the official Python client — used for both reads and writes)
- `httpx` (used by connectors and Sub-Agent 2 for external HTTP calls)
- `openai` (OpenAI SDK)

Run `uv sync` to install. `uv run` auto-syncs before running.

### `.env.example`
Template for the local `.env`. Lists every env var the API needs (Supabase,
OpenAI, NVD, optional Tenable). Real `.env` is gitignored.

### `app/__init__.py`
Empty. Makes `app` a Python package so imports like `app.main` work.

### `app/main.py`
The FastAPI app + the only public HTTP endpoint of the system.

- Creates the FastAPI instance, applies permissive CORS for dev.
- `GET /healthz` → liveness check.
- `POST /agents/trigger`:
  - Validates the request body against `TriggerEvent` (Pydantic model in `models.py`).
  - Looks up `agent_runs` by `event_id`. If a row exists, returns it
    (idempotency — same `event_id` never triggers twice).
  - Otherwise inserts a new row with `status="queued"` and the targets payload.
  - Calls `background_tasks.add_task(run_master, row["run_id"])`. FastAPI
    runs it after the response is returned, so the endpoint never blocks.
  - Returns `201 Created` with `{run_id, event_id, status}`.

This is the **only** way work enters the system. Every other file is reached
indirectly from here.

### `app/config.py`
Single class `Settings(BaseSettings)` that loads env vars from `.env`. All env
vars are lowercase attributes (e.g., `agentic_vop_supabase_url`). Required
vars have no default — startup fails fast if missing. Optional vars default
to empty strings. `extra="ignore"` means unknown env vars don't break startup
(useful when an old var hangs around in `.env`).

`from .config import settings` — used everywhere we need a key.

### `app/db.py`
One function: `supabase_admin()`. Returns a Supabase client instantiated with
the **service_role key** (bypasses Row Level Security). All backend writes go
through this client. Frontend uses the anon key separately.

We deliberately do NOT cache the client across calls — Supabase's Python client
is cheap to construct and not connection-pool-friendly across async contexts.

### `app/models.py`
All Pydantic models the rest of the code depends on. Single file because the
models are intentionally small and shared widely.

- **`TriggerTargets`** + **`TriggerEvent`** — the JSON shape the frontend POSTs to `/agents/trigger`. Mirrors the doc's "input event payload" spec.
- **`RunCreated`** — what `/agents/trigger` returns.
- **`LLMNormalizedIssue`** — Sub-Agent 1's LLM output schema. Used as the `input_schema` for Function calling so the LLM's response is guaranteed-shaped. 13 fields (the canonical normalization output, fields 1–14 of the bigger Issue schema). `model_config = ConfigDict(extra="forbid")` rejects any unknown field from the LLM.
- **`LLMEnrichmentDecision`** — Sub-Agent 2's LLM output schema. 5 fields: `derived_risk` (0–100), `risk_explanation`, `likelihood`, `impact`, `remediation_suggestion`. Same `tool_use` pattern.

Updating any of these = the LLM's output schema updates automatically next call. No prompt changes needed for additive fields.

### `app/agents/__init__.py`
Empty. Makes `agents` a package.

### `app/agents/trace.py`
Single function: `emit_trace(run_id, agent, event_type, message, payload=None)`.
Inserts one row into the `agent_trace_events` table. Realtime is enabled on
that table (set up in migration `0001`), so every emit_trace call is also a
**live UI update** — no separate logging/notification code anywhere.

Used by every agent + Master at every step. Cheap (one row insert, async
Realtime push). Each row is also a permanent audit record.

### `app/agents/llm.py`
Lazy singleton wrapper for the OpenAI client. Reads `OPENAI_API_KEY`
from settings, returns a shared OpenAI client. Both Sub-Agent 1 and
Sub-Agent 2 call `get_client()` and reuse the same instance.

### `app/agents/master.py`
The Master Agent — **LLM-driven**. Loads its own prompt (`master@v1.0` in
`prompt_db`) and uses OpenAI function calling to produce a structured
`MasterPlan`: an ordered list of FETCH and ENRICH steps. Code then executes
the plan step by step, dispatching to Sub-Agent 1 or Sub-Agent 2 per step.

Function: `run_master(run_id)`.

1. Marks `agent_runs.status = "running"`.
2. Emits trace `"Run started, planning"`.
3. Reads the run's `targets.scanners` and the list of available tools from
   `connection_registry`.
4. **Calls `gpt-4o` with the master prompt + run context** to produce a
   `MasterPlan` (Pydantic model in `models.py`). Plan summary + ordered
   steps go straight into a trace event so the user sees the LLM's reasoning.
5. **Executes the plan step by step.** For each `FETCH` step: looks up the
   connector in `connection_registry`, emits a `DISPATCH` trace, calls
   `sub_agent_1.run_fetch(...)`. For each `ENRICH` step: calls
   `sub_agent_2.run_enrich(run_id)`. Per-step errors are caught and reported
   but don't kill other steps.
6. Marks the run completed with a full `summary` JSON (the LLM plan, counts,
   EPSS hits, KEV hits, NVD hits).
7. Emits `SCAN_COMPLETE`.

Top-level try/except wraps everything — any uncaught exception flips the run
to `status="failed"` and emits an ERROR trace. The run never gets stuck
in `"running"`.

The LLM step gives Master the room to make routing decisions later without
code changes (e.g., "skip ENRICH if FETCH returned zero rows", or "fan out
fetch-priority order based on scanner type"). For a single OSV scan today
the plan is trivial — same two steps every time — but the architecture is
ready for richer planning.

### `app/agents/sub_agent_1.py`
The Smart Connector. Three-step pipeline per scanner.

Function: `run_fetch(run_id, tool, registry_entry) -> int` (returns the count of canonical Issues inserted).

**Step 1 — Fetch raw rows.**
- Reads `last_fetched_at` watermark from the registry entry.
- Calls `fetch_raw_rows(...)` from the connector dispatcher (next file).
- Result is a list of dicts — verbatim from whichever scanner.

**Step 2 — Persist verbatim.**
- Bulk-inserts all raw rows into `raw_findings` with `source = tool`,
  `agent_run_id = run_id`, `raw = <the dict>`.
- This gives us a permanent audit record. If we change normalization logic
  later, we can replay from `raw_findings` without re-hitting the scanner.

**Step 3 — Normalize each row via the LLM (parallel).**
- Loads the **single generic** Sub-Agent 1 prompt from `prompt_db` where `agent='sub-agent-1'`.
- Loads **per-scanner mapping rules** from `schema_mapping` for this `tool`.
- Spins up a `ThreadPoolExecutor` with `LLM_PARALLEL_WORKERS` workers (default 5).
- For each persisted raw row, a worker:
  - Builds a JSON message of `{source_scanner, raw_row, mapping_rules}`.
  - Calls OpenAI with function calling against the `LLMNormalizedIssue` schema.
    Up to one in-code retry on JSON parse / Pydantic validation glitches; the
    SDK itself retries 429s up to 10 times with exponential backoff.
  - Validates the returned dict via Pydantic (defense in depth).
  - Inserts a row into `issues` with `raw_finding_id` foreign key pointing to
    the persisted raw row. The first 16 canonical fields populate; the rest
    (enrichment) stay NULL until Sub-Agent 2 runs.
- Tracks errors per-row. First 3 failures emit an ERROR trace with the actual
  exception. Other rows continue independently.

**After processing**: advances `connection_registry.last_fetched_at` only if at
least one row succeeded (so retries see the same data on full failure). Emits
`FETCH_DONE` with all the counts.

### `app/agents/sub_agent_2.py`
The Enrichment Specialist. Hybrid: deterministic data fetch + LLM reasoning.

Function: `run_enrich(run_id) -> dict` (returns counts).

**Step 1 — Load this run's issues + the prompt.**
- `SELECT * FROM issues WHERE agent_run_id = run_id`.
- Loads the `sub-agent-2` prompt from `prompt_db`.

**Step 2 — Collect every unique CVE id** across all issues' `cve_id` and
`all_cves` fields.

**Step 3 — Three deterministic API calls.**
- **EPSS** (FIRST.org public API): single batched call for up to 100 CVEs.
  Returns `epss_score` and `percentile` per CVE.
- **CISA KEV** catalog: one HTTPS download of the full
  `known_exploited_vulnerabilities.json`. Built into a Python `set` for O(1)
  lookup.
- **NVD**: per-CVE call to `https://services.nvd.nist.gov/rest/json/cves/2.0`.
  Throttled to 0.06s with API key (50 req / 30s allowed) or 0.6s without
  (5 req / 30s allowed). Extracts CWE id + CVSS v3.1 vector breakdown.

Helper `_fetch_nvd_data()` does the NVD call with the right throttle.

**Step 4 — LLM decision per issue (parallel).**
- Same `ThreadPoolExecutor` pattern as Sub-Agent 1: `LLM_PARALLEL_WORKERS`
  workers process issues concurrently.
- Helper `_llm_decide(prompt_row, issue, epss, nvd, in_kev)` builds a JSON
  payload of issue + enrichment data and calls OpenAI with function calling
  against the `LLMEnrichmentDecision` schema. Up to one in-code retry on
  glitches; SDK retries 429s.
- The LLM returns: `derived_risk` (0–100), `risk_explanation`, `likelihood`,
  `impact`, `remediation_suggestion`.

**Step 5 — UPDATE the issue row** with all the deterministic enrichment fields
(EPSS, KEV bool, NVD CVSS vector, CWE) plus the LLM-decided fields, and stamp
`enriched_at = now()`.

**After all issues**: emits `ENRICH_DONE` with hit counts (EPSS hits, KEV hits, NVD hits).

### `app/agents/connectors/__init__.py`
The connector dispatcher. Single function: `fetch_raw_rows(tool, registry_entry, last_fetched_at) -> list[dict]`.

Reads `registry_entry.metadata.connector_type` and routes:
- `"osv_api"` → `osv_api.fetch(...)`
- `"tenable_api"` → `tenable_api.fetch(...)`

Anything else raises `ValueError` with a clear message.

This is **the swap point**. Sub-Agent 1 calls one function; the dispatcher
hides which scanner is actually being talked to. Adding a scanner = add a
module + add an `elif` branch.

### `app/agents/connectors/osv_api.py`
Connector for **OSV.dev**, the public Open Source Vulnerabilities database.
Free, no auth, public REST API at `https://api.osv.dev/v1/query`.

Function: `fetch(registry_entry, last_fetched_at) -> list[dict]`.
1. Reads enabled rows from `monitored_packages` table (the list of npm/PyPI/Maven/Go packages we ask OSV about).
2. For each package: POSTs `{package, version}` to `/v1/query`, gets back a list of vulnerabilities.
3. Skips vulns whose `modified` timestamp is ≤ `last_fetched_at` (incremental fetch).
4. **Augments each vuln** with the package context we queried with — adds
   `queried_package_name`, `queried_package_version`, `queried_package_ecosystem`,
   `queried_package_label`. This lets Sub-Agent 1's LLM build `package` and
   `asset_identity` fields without re-joining anything.
5. Returns the flat list.

### `app/agents/connectors/tenable_api.py`
Real connector for a **local Nessus** instance at `https://localhost:8834`.
Uses the legacy `/scans/{id}` + `/plugins/plugin/{id}` endpoints with
`X-ApiKeys` header auth. Currently **not active** in `connection_registry`
(we removed the registration in migration `0010`), but the code is kept so
re-enabling Tenable later is a one-line SQL change.

Disables SSL verification (Nessus uses a self-signed cert on localhost) and
uses a small per-call sleep to be polite to the local instance.

---

## 5. Database tables this code reads/writes

| Table | This code… |
|---|---|
| `agent_runs` | INSERT (main.py), UPDATE status (master.py) |
| `agent_trace_events` | INSERT (every `emit_trace` call) |
| `raw_findings` | INSERT (sub_agent_1.py) |
| `issues` | INSERT (sub_agent_1.py), UPDATE (sub_agent_2.py) |
| `connection_registry` | SELECT + UPDATE last_fetched_at (sub_agent_1.py) |
| `prompt_db` | SELECT (sub_agent_1, sub_agent_2) |
| `schema_mapping` | SELECT (sub_agent_1) |
| `monitored_packages` | SELECT (osv_api.py) |

Tables defined in [`../../supabase/migrations/`](../../supabase/migrations/).

---

## 6. External services this code talks to

| Service | Where | Auth |
|---|---|---|
| **OpenAI** | `agents/llm.py` | `OPENAI_API_KEY` |
| **OSV.dev** | `connectors/osv_api.py` | None |
| **FIRST.org EPSS** | `sub_agent_2.py` | None |
| **CISA KEV** | `sub_agent_2.py` | None |
| **NVD (NIST)** | `sub_agent_2.py` | `NVD_API_KEY` (optional, for higher rate limits) |
| **Local Nessus** | `connectors/tenable_api.py` | `TENABLE_ACCESS_KEY` + `TENABLE_SECRET_KEY` (only if active) |
| **Supabase** | `db.py` (writes) | `AGENTIC_VOP_SUPABASE_SERVICE_KEY` |

All external calls use `httpx` (sync). No async runtime.

---

## 7. Setup

1. **Install [uv](https://github.com/astral-sh/uv):**
   ```
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Apply database migrations** (only once). See [`../../supabase/README.md`](../../supabase/README.md).

3. **Copy the env template and fill in:**
   ```
   cp .env.example .env
   ```
   Required:
   - `AGENTIC_VOP_SUPABASE_URL` — your Supabase project URL
   - `AGENTIC_VOP_SUPABASE_SERVICE_KEY` — Dashboard → Settings → API → "service_role secret" (the LONGER key — bypasses RLS)
   - `OPENAI_API_KEY`

   Optional (but recommended):
   - `NVD_API_KEY` — free at https://nvd.nist.gov/developers/request-an-api-key. Without it, NVD lookups are rate-limited to 5 req / 30 sec.

4. **Run the dev server:**
   ```
   uv run uvicorn app.main:app --reload --port 8000
   ```
   uv creates `.venv/` on first run, installs everything, then runs uvicorn
   with hot-reload.

---

## 8. Smoke test

```
# Liveness
curl http://localhost:8000/healthz
# → {"status":"ok"}

# Trigger a real run
curl -X POST http://localhost:8000/agents/trigger \
  -H "Content-Type: application/json" \
  -d '{"event_id":"EVT-test-001","action":"FETCH","targets":{"scanners":["osv"]}}'
# → {"run_id":"...","event_id":"EVT-test-001","status":"queued"}
```

The endpoint returns immediately. The Master Agent runs in the background.
Watch progress on the frontend's **Agents** page (Realtime feed) or by
querying `agent_trace_events`.

Run the same `event_id` twice — second call returns the same `run_id` and
does **not** re-trigger (idempotency).

---

## 9. Endpoints

| Method | Path | What it does |
|---|---|---|
| `GET`  | `/healthz`         | Liveness check |
| `POST` | `/agents/trigger`  | Persist a run, kick off Master in background |

Two endpoints — that's it. Everything else happens via the agents writing to
Supabase, with the frontend subscribed to Realtime updates.

---

## 10. Environment variables reference

| Var | Required? | What |
|---|---|---|
| `AGENTIC_VOP_SUPABASE_URL` | yes | Your Supabase project URL |
| `AGENTIC_VOP_SUPABASE_SERVICE_KEY` | yes | service_role key (bypasses RLS) |
| `OPENAI_API_KEY` | yes | OpenAI API access |
| `NVD_API_KEY` | optional | Free; lifts NVD rate limit from 5 → 50 req / 30 sec |
| `LLM_PARALLEL_WORKERS` | optional | Thread pool size for Sub-Agent 1 + Sub-Agent 2 LLM calls. Default `5`. Bump to `10`+ on Tier-2 OpenAI accounts; drop to `3` if you hit 429s on default tier. |
| `TENABLE_ACCESS_KEY` | optional | Only used if the Tenable connector is active in registry |
| `TENABLE_SECRET_KEY` | optional | Pair to TENABLE_ACCESS_KEY |

Loaded by `config.py` via pydantic-settings. Unknown env vars are silently
ignored — old `OLD_SUPABASE_*` lines from earlier development can stay in
`.env` without breaking startup.

---

## 11. How to add a new scanner

1. **Write a connector** under `app/agents/connectors/<scanner>_api.py`. Follow the pattern of `osv_api.py` — function signature is `fetch(registry_entry, last_fetched_at) -> list[dict]`. Each returned dict is a raw row in whatever shape; Sub-Agent 1's LLM does the normalization.

2. **Register dispatch** in `connectors/__init__.py` — add an `elif connector_type == "<scanner>_api"` branch.

3. **SQL `INSERT`** into `connection_registry` with `tool` and `metadata = {"connector_type": "<scanner>_api"}`.

4. **SQL `INSERT`** per-scanner translation rules into `schema_mapping` describing how to map raw fields to canonical Issue fields.

5. **Add the scanner** to the UI's `SCANNERS` constant in `apps/web/src/pages/Integrations.jsx`.

No new prompts. No agent code changes. The generic Sub-Agent 1 prompt + the
mapping rules in the DB handle everything else.

---

## 12. Glossary (for newcomers)

- **Master Agent** — the orchestrator. Receives a trigger, dispatches to sub-agents, aggregates results.
- **Sub-Agent 1 (Smart Connector)** — talks to one scanner at a time, fetches raw findings, persists them, normalizes each into the canonical Issue shape via the LLM.
- **Sub-Agent 2 (Enrichment Specialist)** — for every Issue, fetches EPSS / KEV / NVD data and asks the LLM to produce a risk score with explanation + remediation.
- **Connector** — the per-scanner code that knows how to talk to a specific external service (OSV's REST API, Nessus's REST API, etc.).
- **Connector dispatcher** — routes Sub-Agent 1 to the right connector based on the scanner's `connector_type` registered in the database.
- **Canonical Issue** — the platform's unified vulnerability schema (33 fields). Every scanner's output gets translated into this shape.
- **Watermark** — `last_fetched_at` per connector. Used for incremental fetch — only pull what's new since the last successful run.
- **Idempotency key** — the `event_id` on the trigger payload. Prevents duplicate runs.
- **`tool_use`** — Function-calling feature where the LLM is told "call this function with these typed arguments." API enforces the schema; we get structured data without parsing.
- **Trace event** — one row in `agent_trace_events`, written by any agent at any step. Drives the live Agents page in the UI.
- **Run** — one execution of the pipeline, identified by `run_id`. Owns its own trace events, raw_findings, and issues.
