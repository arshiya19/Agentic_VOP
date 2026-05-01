# Agentic_VOP Web

The frontend of Agentic_VOP — React + Vite + Supabase.

This is what users see at `http://localhost:5173`. It handles login, navigation,
the **Integrations** page (where users trigger a scan), and the **Agents** page
(where the live trace of master + sub-agents streams in real time as they work).

> The bigger picture lives in the [project README](../../README.md).
> The backend is in [`../api/`](../api/).

## What's inside

```
apps/web/
├── package.json            # npm deps
├── vite.config.js          # Vite config
├── tailwind.config.js      # Tailwind 3 config
├── eslint.config.js        # ESLint
├── index.html              # HTML entry
├── public/                 # Static assets
├── .env                    # Frontend env (gitignored)
├── .env.example            # Template
└── src/
    ├── main.jsx            # React Router setup — every route mounted here
    ├── App.jsx             # Chat shell (legacy from earlier prototype, mostly unused)
    ├── App.css, index.css  # Global styles
    ├── lib/
    │   └── supabase.js     # Supabase client (anon key) — used for auth + Realtime subscriptions
    ├── contexts/
    │   └── AuthContext.jsx # Login state, signIn / signUp / signOut, user role,
    │                       # plus a BYPASS_AUTH dev escape hatch (set in .env)
    ├── components/         # Reusable UI pieces
    │   ├── Topbar.jsx, Sidebar.jsx           # Layout chrome on every authenticated page
    │   ├── ProtectedRoute.jsx                # Wraps pages requiring auth
    │   ├── ColumnToggle.jsx, MultiSelectFilter.jsx, SeverityFilter.jsx,
    │   │   ViewToggleEye.jsx, Tooltip.jsx    # Generic widgets
    │   └── icons/SidebarIcons.jsx            # SVG icon dictionary
    ├── pages/              # One file per route
    │   ├── Login.jsx, Signup.jsx
    │   ├── Agents.jsx           # Live trace UI (subscribes to Supabase Realtime)
    │   ├── Integrations.jsx     # "Run a scan" panel + scanner cards (POSTs to backend)
    │   ├── Issues.jsx, Dashboard.jsx
    │   └── (other pages — Activity, Reports, Alerts, Policies, etc. — UI shells, not yet wired)
    └── styles/             # One CSS file per page (Agents.css, Issues.css, ...)
```

## How it talks to the rest of the system

```
                ┌─────────────────────────────────┐
                │   Supabase                      │
                │   (auth + DB + Realtime)        │
                └────┬─────────────────┬──────────┘
                     │                 │
              auth + Realtime          │
                     │                 │
                     ▼                 │
            ┌────────────────┐         │
            │  Frontend      │         │
            │  apps/web      │         │
            │  localhost:5173│         │
            └────────┬───────┘         │
                     │                 │ writes
        POST /agents/trigger           │
                     │                 │
                     ▼                 ▼
            ┌──────────────────────────────────────┐
            │  Backend (apps/api, localhost:8000)  │
            │  Runs master + sub-agents            │
            └──────────────────────────────────────┘
```

The frontend talks to **Supabase directly** for auth + Realtime trace
subscriptions, and to the **backend at localhost:8000** to trigger runs.

## Pages — what's wired vs what's a shell

**Wired to live data** (these show real things):

| Page | Path | What it does |
|---|---|---|
| **Agents** | `/agents` | Live trace of every master + sub-agent step. Subscribes to `agent_trace_events` + `agent_runs` via Supabase Realtime. The 4 KPI cards and the agents panel update in real time. |
| **Integrations** | `/integrations` | The **"Run a scan"** panel at the top has the scanner cards (today: OSV.dev). Clicking a card + **Fetch findings** triggers a real run via `POST localhost:8000/agents/trigger`. The button stays disabled for 5 seconds after each successful trigger to prevent accidental rapid-clicks creating duplicate runs. The categories panel below is a static catalog of would-be future integrations. |
| **Login / Signup** | `/login`, `/signup` | Real Supabase Auth. |

**UI shells** (rendered, but not connected to real data yet):

| Page | Why |
|---|---|
| Dashboard, Issues, Reports, Alerts, Activity, Policies, Validation, Remediation, Assets, Settings | Layouts ready, will be wired to the `issues` table + queries when needed. |

## One-time setup

1. **Apply database migrations first** — see [`../../supabase/README.md`](../../supabase/README.md). The frontend's auth + Realtime subscriptions assume the Supabase tables already exist.

2. **Copy and fill in env vars:**
   ```
   cp .env.example .env
   ```
   You need:
   - `VITE_SUPABASE_URL` — your project URL (same as the backend's `AGENTIC_VOP_SUPABASE_URL`)
   - `VITE_SUPABASE_ANON_KEY` — Dashboard → Settings → API → **anon public** (the SHORTER one; never use service_role in the frontend)
   - `VITE_API_BASE_URL` — backend URL (`http://localhost:8000` for dev)
   - `VITE_BYPASS_AUTH` — leave as `false` for normal use; set `true` only if you want to skip Supabase Auth and get a mock admin user for quick UI iteration

3. **Install deps + run the dev server:**
   ```
   npm install
   npm run dev
   ```
   Vite serves at `http://localhost:5173` with hot-reload.

## End-to-end demo flow

1. Make sure the backend (`apps/api`) is running at `localhost:8000`.
2. Open `localhost:5173` → log in (or sign up — Supabase Auth handles it).
3. Sidebar → **Integrations** → click the **OSV.dev** card → click **Fetch findings**. UI fires a POST to the backend.
4. Sidebar → **Agents**. Watch the trace events stream in newest-first. The 4 stat cards update live (Active Agents, Tasks In Flight, Completed today, Errors today). Master and both sub-agents in the left panel get green "working" dots while the run is in flight.
5. After ~5–10 minutes the run reaches `SCAN_COMPLETE`. Stat cards settle.
6. (Optional) Open Supabase Dashboard → Table Editor → `issues` to see the canonical findings, each with `risk_explanation` and `remediation_suggestion` written by the LLM.

## How the Agents page stays live without polling

[`pages/Agents.jsx`](src/pages/Agents.jsx) opens two Supabase Realtime channels:

```js
supabase.channel('agent-trace-stream')
  .on('postgres_changes', { event: 'INSERT', table: 'agent_trace_events' }, ...)
  .subscribe()

supabase.channel('agent-runs-stream')
  .on('postgres_changes', { event: '*', table: 'agent_runs' }, ...)
  .subscribe()
```

Realtime is enabled on both tables in migration `0001`. Every time the
backend inserts or updates a row, Supabase pushes the change directly to
every subscribed client. No polling, no refresh button.

## Adding a new scanner card

Edit `src/pages/Integrations.jsx`, find the `SCANNERS` constant near the top:
```js
const SCANNERS = [
  { tool: 'osv', label: 'OSV.dev' },
  // add new entries here
]
```
The `tool` value must match what's in `connection_registry.tool` on the backend.

## Tech stack

| | |
|---|---|
| Framework | React 19 |
| Bundler / dev server | Vite 7 |
| Routing | react-router-dom 7 |
| Styling | Tailwind 3 + per-page CSS files |
| Auth | Supabase Auth (`@supabase/supabase-js`) |
| Real-time updates | Supabase Realtime (Postgres LISTEN/NOTIFY under the hood) |
| Charts | recharts (used on Dashboard, where wired) |
