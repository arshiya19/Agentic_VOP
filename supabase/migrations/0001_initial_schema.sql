-- =============================================================================
-- Agentic_VOP — initial schema (v1)
-- =============================================================================
-- 6 tables organized in two groups:
--   Operational (per-run data):  agent_runs, agent_trace_events, issues
--   Configuration (set up once): connection_registry, schema_mapping, prompt_db
--
-- Apply by pasting into Supabase Dashboard SQL Editor for project agentic-vop-dev.
-- =============================================================================

-- pgcrypto for gen_random_uuid() (Supabase enables by default; included for safety)
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =============================================================================
-- 1. agent_runs — receipt for each user trigger
-- =============================================================================
CREATE TABLE agent_runs (
  run_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      text UNIQUE NOT NULL,
  triggered_by  text NOT NULL,
  action        text NOT NULL CHECK (action IN ('FETCH','ENRICH','FULL')),
  targets       jsonb NOT NULL DEFAULT '{}'::jsonb,
  status        text NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','completed','failed')),
  started_at    timestamptz NOT NULL DEFAULT now(),
  completed_at  timestamptz,
  summary       jsonb,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_agent_runs_status     ON agent_runs(status);
CREATE INDEX idx_agent_runs_started_at ON agent_runs(started_at DESC);

COMMENT ON TABLE agent_runs IS
  'One row per user-triggered run. Idempotency keyed on event_id.';


-- =============================================================================
-- 2. agent_trace_events — live activity feed (Agents page subscribes via Realtime)
-- =============================================================================
CREATE TABLE agent_trace_events (
  id          bigserial PRIMARY KEY,
  run_id      uuid NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
  agent       text NOT NULL
                CHECK (agent IN ('master','sub-agent-1','sub-agent-2','system')),
  event_type  text NOT NULL
                CHECK (event_type IN ('DISPATCH','MESSAGE','DONE','ERROR')),
  message     text NOT NULL,
  payload     jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_trace_events_run_id_time
  ON agent_trace_events(run_id, created_at);

COMMENT ON TABLE agent_trace_events IS
  'Step-by-step trace of agent activity within a run. Streamed to UI via Supabase Realtime.';


-- =============================================================================
-- 3. issues — canonical 33-field findings table
-- =============================================================================
CREATE TABLE issues (
  id  bigserial PRIMARY KEY,

  -- ---- Sub-Agent 1 (normalization, fields 1-16) ----
  fingerprint     text UNIQUE NOT NULL,
  source          text NOT NULL
                    CHECK (source IN ('tenable','trivy','qualys','owasp','snyk')),
  source_vuln_id  text NOT NULL,
  cve_id          text,
  all_cves        text[] NOT NULL DEFAULT '{}',
  title           text NOT NULL,
  description     text,
  severity        text NOT NULL
                    CHECK (severity IN ('Info','Low','Medium','High','Critical')),
  cvss_score      numeric(3,1),
  cvss_version    text CHECK (cvss_version IN ('2.0','3.0','3.1')),
  solution        text,
  asset_identity  jsonb NOT NULL DEFAULT '{}'::jsonb,
  package         jsonb,
  first_detected  timestamptz,
  source_raw      jsonb NOT NULL,
  agent_run_id    uuid REFERENCES agent_runs(run_id) ON DELETE SET NULL,

  -- ---- Sub-Agent 2 (enrichment, fields 17-33) ----
  cwe_id                    text,
  cwe_name                  text,
  epss_score                numeric(5,4),
  epss_percentile           numeric(5,4),
  cvss_attack_vector        text CHECK (cvss_attack_vector IN ('NETWORK','ADJACENT','LOCAL','PHYSICAL')),
  cvss_attack_complexity    text CHECK (cvss_attack_complexity IN ('LOW','HIGH')),
  cvss_privileges_required  text CHECK (cvss_privileges_required IN ('NONE','LOW','HIGH')),
  cvss_user_interaction     text CHECK (cvss_user_interaction IN ('NONE','REQUIRED')),
  exploit_in_kev            boolean NOT NULL DEFAULT false,
  exposure                  text CHECK (exposure IN ('public','internal')),
  business_criticality      smallint CHECK (business_criticality BETWEEN 1 AND 5),
  asset_owner               text,
  likelihood                numeric(4,3) CHECK (likelihood BETWEEN 0 AND 1),
  impact                    numeric(4,3) CHECK (impact BETWEEN 0 AND 1),
  derived_risk              numeric(5,2) CHECK (derived_risk BETWEEN 0 AND 100),
  estimated_loss_usd        numeric(15,2),
  enriched_at               timestamptz,

  -- ---- audit ----
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_issues_severity        ON issues(severity);
CREATE INDEX idx_issues_derived_risk    ON issues(derived_risk DESC NULLS LAST);
CREATE INDEX idx_issues_cve_id          ON issues(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_issues_source          ON issues(source);
CREATE INDEX idx_issues_agent_run_id    ON issues(agent_run_id);
CREATE INDEX idx_issues_first_detected  ON issues(first_detected DESC NULLS LAST);

COMMENT ON TABLE issues IS
  'Canonical findings table. 33 fields. Sub-Agent 1 fills 1-16; Sub-Agent 2 fills 17-33.';


-- =============================================================================
-- 4. connection_registry — tool -> protocol/auth mapping
-- =============================================================================
CREATE TABLE connection_registry (
  tool            text PRIMARY KEY,
  protocol        text NOT NULL CHECK (protocol IN ('REST','MCP','FILE','GRAPHQL')),
  auth_type       text NOT NULL,
  endpoint        text NOT NULL,
  auth_ref        text NOT NULL,
  rate_limit_rpm  integer,
  timeout_sec     integer NOT NULL DEFAULT 30,
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
  enabled         boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE connection_registry IS
  'Lookup of how to connect to each scanner. One row per scanner.';


-- =============================================================================
-- 5. schema_mapping — translation rules per scanner field
-- =============================================================================
CREATE TABLE schema_mapping (
  id               bigserial PRIMARY KEY,
  scanner          text NOT NULL,
  source_field     text NOT NULL,
  canonical_field  text NOT NULL,
  transform        jsonb NOT NULL DEFAULT '{"type":"direct"}'::jsonb,
  notes            text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scanner, source_field, canonical_field)
);

CREATE INDEX idx_schema_mapping_scanner ON schema_mapping(scanner);

COMMENT ON TABLE schema_mapping IS
  'Translation rules used by Sub-Agent 1 to map raw scanner fields to canonical Issue fields.';


-- =============================================================================
-- 6. prompt_db — versioned agent prompts
-- =============================================================================
CREATE TABLE prompt_db (
  id           bigserial PRIMARY KEY,
  agent        text NOT NULL,
  version      text NOT NULL,
  model        text NOT NULL,
  prompt_text  text NOT NULL,
  parameters   jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_active    boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agent, version)
);

CREATE INDEX idx_prompt_db_active
  ON prompt_db(agent) WHERE is_active = true;

COMMENT ON TABLE prompt_db IS
  'Versioned prompts for every agent. Loaded at runtime; allows tweaks without redeploys.';


-- =============================================================================
-- updated_at trigger (shared across tables that need it)
-- =============================================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_issues_updated_at
  BEFORE UPDATE ON issues
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_connection_registry_updated_at
  BEFORE UPDATE ON connection_registry
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_schema_mapping_updated_at
  BEFORE UPDATE ON schema_mapping
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- =============================================================================
-- Realtime — push inserts/updates to subscribed clients (Agents page, etc.)
-- =============================================================================
ALTER PUBLICATION supabase_realtime ADD TABLE agent_trace_events;
ALTER PUBLICATION supabase_realtime ADD TABLE agent_runs;
ALTER PUBLICATION supabase_realtime ADD TABLE issues;


-- =============================================================================
-- Row-Level Security — minimal v1 posture
-- =============================================================================
-- Authenticated users can READ all tables (single-tenant dev posture).
-- Backend (using service_role key) bypasses RLS for writes.

ALTER TABLE agent_runs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_trace_events  ENABLE ROW LEVEL SECURITY;
ALTER TABLE issues              ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE schema_mapping      ENABLE ROW LEVEL SECURITY;
ALTER TABLE prompt_db           ENABLE ROW LEVEL SECURITY;

CREATE POLICY "auth read" ON agent_runs          FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth read" ON agent_trace_events  FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth read" ON issues              FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth read" ON connection_registry FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth read" ON schema_mapping      FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth read" ON prompt_db           FOR SELECT TO authenticated USING (true);
