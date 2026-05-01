# Agentic_VOP

A multi-agent vulnerability management platform. Connects to vulnerability scanners,
normalizes their output into a single canonical schema, enriches every finding with
real exploit-intelligence (EPSS, CISA KEV, NVD, and others), and serves it through
a live UI that shows the agents working in real time.

The pipeline is **agent-driven**: a master orchestrator dispatches tasks to two
specialized sub-agents (a Smart Connector and an Enrichment Specialist), each
backed by Claude. Per-scanner knowledge is stored in the database — adding a new
scanner is a SQL `INSERT`, not a code deploy.

## Architecture at a glance

```
┌────────────────────────────────────────────────────────────┐
│                      USER (browser)                        │
│                  Integrations page → click                 │
└──────────────────────────┬─────────────────────────────────┘
                           │ POST /agents/trigger
                           ▼
┌────────────────────────────────────────────────────────────┐
│        FastAPI gateway (apps/api)                          │
│  Persists run, kicks off Master in background              │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│        MASTER AGENT (orchestrator)                         │
│  Plans, dispatches, aggregates, marks SCAN_COMPLETE        │
└──────┬──────────────────────────────────────┬──────────────┘
       │                                      │
       ▼                                      ▼
┌──────────────────────────┐   ┌──────────────────────────────┐
│ SUB-AGENT 1              │   │ SUB-AGENT 2                  │
│ Smart Connector          │   │ Enrichment Specialist        │
│ • Fetch from scanner     │   │ • Hits EPSS, CISA KEV, NVD   │
│ • Persist raw verbatim   │   │ • LLM decides risk +         │
│ • LLM normalizes to      │   │   remediation per issue      │
│   canonical schema       │   │                              │
└──────────────────────────┘   └──────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│        SUPABASE (Postgres + Auth + Realtime)               │
│  Stores: agent_runs, agent_trace_events, raw_findings,     │
│          issues, connection_registry, prompt_db, …         │
│  Realtime pushes traces to the UI as they happen           │
└────────────────────────────────────────────────────────────┘
                           ▲
                           │ Realtime subscription
                           │
┌────────────────────────────────────────────────────────────┐
│       Frontend (apps/web) — Agents page                    │
│  Live trace of master + sub-agents working                 │
└────────────────────────────────────────────────────────────┘
```

## Repository layout

```
Agentic_VOP/
├── apps/
│   ├── api/        # Backend (FastAPI + agents) — Python 3.11+
│   └── web/        # Frontend (React + Vite + Supabase) — JavaScript
├── supabase/
│   └── migrations/ # SQL files — full database schema as code
└── README.md       # This file
```

Three top-level pieces:

- **`apps/api/`** — the brains. Master Agent, Sub-Agent 1, Sub-Agent 2, the
  Anthropic SDK wrapper, the connectors that talk to external scanners. See
  [apps/api/README.md](apps/api/README.md) for the inside tour.

- **`apps/web/`** — the eyes. Login, sidebar navigation, the **Agents page**
  (live trace driven by Supabase Realtime), the **Integrations page** (trigger
  scans). See [apps/web/README.md](apps/web/README.md).

- **`supabase/migrations/`** — the database, expressed as a numbered SQL series.
  Apply each file in order in the Supabase Dashboard SQL Editor.
  See [supabase/README.md](supabase/README.md).

## Quick start (full local pipeline)

You'll need **Supabase** (a free tier project), an **Anthropic API key**, and
optionally an **NVD API key** (for faster CVE lookups).

### 1. Apply the database migrations

In your Supabase Dashboard → SQL Editor → for each file in
`supabase/migrations/` (in order, `0001` through `0011`): paste, run.

That builds the 8 tables, seeds the OSV connector, and registers the agent
prompts.

### 2. Backend

```
cd apps/api
cp .env.example .env
# Fill in the Supabase URL + service_role key, Anthropic key, NVD key
uv run uvicorn app.main:app --reload --port 8000
```

### 3. Frontend

```
cd apps/web
cp .env.example .env
# Fill in the same Supabase URL + anon key (NOT service_role)
npm install
npm run dev
```

### 4. Trigger your first run

Open `http://localhost:5173` → log in (or sign up) → **Integrations** →
click the **OSV.dev** card → click **Fetch findings**.

Switch to the **Agents** page and watch the trace stream in.

## How a single run flows (per pipeline)

1. User clicks **Fetch findings**. UI POSTs to `/agents/trigger` with an
   `event_id` for idempotency.
2. API persists a row in `agent_runs` (status `queued`), kicks off the Master
   Agent as a background task, returns instantly.
3. Master flips status to `running`, emits the first trace event, looks up
   the OSV connector in `connection_registry`.
4. Master dispatches FETCH to **Sub-Agent 1**.
5. Sub-Agent 1 reads `monitored_packages`, hits `https://api.osv.dev/v1/query`,
   bulk-inserts every raw vulnerability record into `raw_findings`, then loops:
   for each raw row → calls Claude with the generic Sub-Agent 1 prompt + the
   per-scanner mapping rules from `schema_mapping` → inserts the canonical
   Issue into `issues`.
6. Sub-Agent 1 emits FETCH_DONE. Master receives it and dispatches ENRICH to
   **Sub-Agent 2**.
7. Sub-Agent 2 makes batched lookups to **EPSS** (FIRST.org), downloads the
   **CISA KEV** catalog, and hits **NVD** per CVE. For each Issue, it calls
   Claude with the assembled enrichment data; Claude returns a structured
   decision (`derived_risk`, `risk_explanation`, `likelihood`, `impact`,
   `remediation_suggestion`).
8. Sub-Agent 2 emits ENRICH_DONE. Master writes SCAN_COMPLETE and marks the
   run completed with a full summary.

Throughout, every step writes a row to `agent_trace_events`. Supabase Realtime
pushes those rows to the **Agents** page in the browser, so the user watches
the agents working step by step.

## Key external services

| Service | Used for | Auth required |
|---|---|---|
| **Supabase** | Auth, database, real-time pub/sub | URL + anon key (frontend), service_role key (backend) |
| **Anthropic Claude** | LLM reasoning (Haiku 4.5) for both sub-agents | API key |
| **OSV.dev** | Live source of vulnerabilities | None (public API) |
| **FIRST.org EPSS** | Exploit probability per CVE | None |
| **CISA KEV** | Actively-exploited CVE catalog | None |
| **NVD (NIST)** | CWE id + CVSS v3 vector breakdown | API key recommended (faster) |

## Adding a new scanner

This is the architectural payoff. To onboard, say, GitHub Advisory:

1. Write a new connector module under `apps/api/app/agents/connectors/`
   (one file, ~80 lines following the pattern of `osv_api.py`).
2. Register the dispatch case in `connectors/__init__.py`.
3. SQL `INSERT` into `connection_registry` with `metadata.connector_type =
   "github_advisory_api"`.
4. SQL `INSERT` mapping rules into `schema_mapping` for the new scanner.
5. Add the card to the UI scanner list in `apps/web/src/pages/Integrations.jsx`.

No prompt changes. No agent code changes. The generic Sub-Agent 1 prompt
already handles any scanner whose mapping rules exist in the database.

## Where to look for what

| Looking for… | Open this |
|---|---|
| The user trigger flow | `apps/api/app/main.py` |
| Master orchestration | `apps/api/app/agents/master.py` |
| The connector dispatcher | `apps/api/app/agents/connectors/__init__.py` |
| Real OSV fetch logic | `apps/api/app/agents/connectors/osv_api.py` |
| Sub-Agent 1 normalization | `apps/api/app/agents/sub_agent_1.py` |
| Sub-Agent 2 enrichment + LLM decision | `apps/api/app/agents/sub_agent_2.py` |
| The canonical Issue schema | `apps/api/app/models.py` |
| The Agents page (live trace) | `apps/web/src/pages/Agents.jsx` |
| The trigger UI | `apps/web/src/pages/Integrations.jsx` |
| Database tables | `supabase/migrations/0001_initial_schema.sql` |
| Active LLM prompts | `prompt_db` table — `SELECT agent, version, prompt_text FROM prompt_db WHERE is_active` |
