-- =============================================================================
-- Agentic_VOP — Dev schema for local development isolation
-- =============================================================================
-- Creates a `dev` Postgres schema that mirrors all 16 public tables.
-- When the API runs with DB_SCHEMA=dev, supabase_admin() targets dev.* instead
-- of public.*, giving full isolation between local dev and production data.
--
-- The demo schema (migration 0046) is NOT affected — supabase_admin_demo()
-- remains hardcoded to "demo".
--
-- After running this migration, seed dev tables from public:
--   INSERT INTO dev.<table> SELECT * FROM public.<table>;
-- (See seed script at the bottom of this file.)
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS dev;

-- Grant usage to the service role so supabase-py .schema("dev") works.
GRANT USAGE ON SCHEMA dev TO service_role;
GRANT ALL ON ALL TABLES IN SCHEMA dev TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA dev TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA dev GRANT ALL ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA dev GRANT ALL ON SEQUENCES TO service_role;

-- Also grant to authenticated role (for RLS policies / realtime if needed).
GRANT USAGE ON SCHEMA dev TO authenticated;


-- =============================================================================
-- 1. agent_runs
-- =============================================================================
CREATE TABLE dev.agent_runs (
  run_id       uuid        NOT NULL DEFAULT gen_random_uuid(),
  event_id     text        NOT NULL,
  triggered_by text        NOT NULL,
  action       text        NOT NULL,
  targets      jsonb       NOT NULL DEFAULT '{}'::jsonb,
  status       text        NOT NULL DEFAULT 'queued'::text,
  started_at   timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  summary      jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  cancellation_requested boolean NOT NULL DEFAULT false,

  CONSTRAINT dev_agent_runs_pkey PRIMARY KEY (run_id),
  CONSTRAINT dev_agent_runs_event_id_key UNIQUE (event_id),
  CONSTRAINT dev_agent_runs_action_check CHECK (action IN ('FETCH','ENRICH','FULL')),
  CONSTRAINT dev_agent_runs_status_check CHECK (status IN ('queued','running','completed','failed','cancelled'))
);

CREATE INDEX idx_dev_agent_runs_started_at ON dev.agent_runs (started_at DESC);
CREATE INDEX idx_dev_agent_runs_status ON dev.agent_runs (status);


-- =============================================================================
-- 2. agent_trace_events
-- =============================================================================
CREATE TABLE dev.agent_trace_events (
  id         bigserial   NOT NULL,
  run_id     uuid        NOT NULL,
  agent      text        NOT NULL,
  event_type text        NOT NULL,
  message    text        NOT NULL,
  payload    jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_agent_trace_events_pkey PRIMARY KEY (id),
  CONSTRAINT dev_agent_trace_events_run_id_fkey FOREIGN KEY (run_id) REFERENCES dev.agent_runs(run_id) ON DELETE CASCADE,
  CONSTRAINT dev_agent_trace_events_agent_check CHECK (agent IN ('master','sub-agent-1','sub-agent-2','sub-agent-3','sub-agent-4','system')),
  CONSTRAINT dev_agent_trace_events_event_type_check CHECK (event_type IN ('DISPATCH','MESSAGE','DONE','ERROR'))
);

CREATE INDEX idx_dev_trace_events_run_id_time ON dev.agent_trace_events (run_id, created_at);


-- =============================================================================
-- 3. raw_findings
-- =============================================================================
CREATE TABLE dev.raw_findings (
  id           bigserial   NOT NULL,
  source       text        NOT NULL,
  agent_run_id uuid,
  raw          jsonb       NOT NULL,
  fetched_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_raw_findings_pkey PRIMARY KEY (id),
  CONSTRAINT dev_raw_findings_agent_run_id_fkey FOREIGN KEY (agent_run_id) REFERENCES dev.agent_runs(run_id)
);

CREATE INDEX idx_dev_raw_findings_agent_run_id ON dev.raw_findings (agent_run_id);
CREATE INDEX idx_dev_raw_findings_fetched_at ON dev.raw_findings (fetched_at DESC);
CREATE INDEX idx_dev_raw_findings_source ON dev.raw_findings (source);


-- =============================================================================
-- 4. issues
-- =============================================================================
CREATE TABLE dev.issues (
  id                          bigserial   NOT NULL,
  source                      text        NOT NULL,
  source_vuln_id              text        NOT NULL,
  cve_id                      text,
  all_cves                    text[]      NOT NULL DEFAULT '{}'::text[],
  title                       text        NOT NULL,
  description                 text,
  severity                    text        NOT NULL,
  cvss_score                  numeric,
  cvss_version                text,
  solution                    text,
  asset_identity              jsonb       NOT NULL DEFAULT '{}'::jsonb,
  package                     jsonb,
  first_detected              timestamptz,
  agent_run_id                uuid,
  cwe_id                      text,
  cwe_name                    text,
  epss_score                  numeric,
  epss_percentile             numeric,
  cvss_attack_vector          text,
  cvss_attack_complexity      text,
  cvss_privileges_required    text,
  cvss_user_interaction       text,
  exploit_in_kev              boolean     NOT NULL DEFAULT false,
  exposure                    text,
  business_criticality        smallint,
  asset_owner                 text,
  likelihood                  numeric,
  impact                      numeric,
  derived_risk                numeric,
  estimated_loss_usd          numeric,
  enriched_at                 timestamptz,
  created_at                  timestamptz NOT NULL DEFAULT now(),
  updated_at                  timestamptz NOT NULL DEFAULT now(),
  raw_finding_id              bigint,
  risk_explanation            text,
  remediation_suggestion      text,
  cwe_likelihood_of_exploit   text,
  cwe_abstraction             text,
  cwe_mitigation_phases       text[]      NOT NULL DEFAULT '{}'::text[],
  capec_ids                   text[]      NOT NULL DEFAULT '{}'::text[],
  capec_max_likelihood_of_attack text,
  capec_max_typical_severity  text,
  attack_technique_ids        text[]      NOT NULL DEFAULT '{}'::text[],
  attack_tactics              text[]      NOT NULL DEFAULT '{}'::text[],
  attack_platforms            text[]      NOT NULL DEFAULT '{}'::text[],
  components_summary          jsonb       NOT NULL DEFAULT '{}'::jsonb,
  priority                    text,
  scoring_policy_version      text,
  cvss_vector                 text,
  runtime_hostname            text,
  runtime_ipv4                text,
  runtime_os_raw              text,
  runtime_os_family           text,
  runtime_distro_version      text,
  runtime_purl                text,
  runtime_image_id            text,

  CONSTRAINT dev_issues_pkey PRIMARY KEY (id),
  CONSTRAINT dev_issues_agent_run_id_fkey FOREIGN KEY (agent_run_id) REFERENCES dev.agent_runs(run_id),
  CONSTRAINT dev_issues_raw_finding_id_fkey FOREIGN KEY (raw_finding_id) REFERENCES dev.raw_findings(id),
  CONSTRAINT dev_issues_severity_check CHECK (severity IN ('Info','Low','Medium','High','Critical')),
  CONSTRAINT dev_issues_cvss_version_check CHECK (cvss_version IS NULL OR cvss_version IN ('2.0','3.0','3.1','4.0')),
  CONSTRAINT dev_issues_cvss_attack_vector_check CHECK (cvss_attack_vector IN ('NETWORK','ADJACENT','LOCAL','PHYSICAL')),
  CONSTRAINT dev_issues_cvss_attack_complexity_check CHECK (cvss_attack_complexity IN ('LOW','HIGH')),
  CONSTRAINT dev_issues_cvss_privileges_required_check CHECK (cvss_privileges_required IN ('NONE','LOW','HIGH')),
  CONSTRAINT dev_issues_cvss_user_interaction_check CHECK (cvss_user_interaction IN ('NONE','REQUIRED')),
  CONSTRAINT dev_issues_exposure_check CHECK (exposure IN ('public','internal')),
  CONSTRAINT dev_issues_business_criticality_check CHECK (business_criticality >= 1 AND business_criticality <= 5),
  CONSTRAINT dev_issues_likelihood_check CHECK (likelihood >= 0 AND likelihood <= 1),
  CONSTRAINT dev_issues_impact_check CHECK (impact >= 0 AND impact <= 1),
  CONSTRAINT dev_issues_derived_risk_check CHECK (derived_risk >= 0 AND derived_risk <= 100),
  CONSTRAINT dev_issues_priority_check CHECK (priority IS NULL OR priority IN ('P0','P1','P2','P3')),
  CONSTRAINT dev_issues_cwe_likelihood_of_exploit_check CHECK (cwe_likelihood_of_exploit IS NULL OR cwe_likelihood_of_exploit IN ('Low','Medium','High')),
  CONSTRAINT dev_issues_cwe_abstraction_check CHECK (cwe_abstraction IS NULL OR cwe_abstraction IN ('Base','Class','Variant','Compound','Pillar')),
  CONSTRAINT dev_issues_capec_max_likelihood_of_attack_check CHECK (capec_max_likelihood_of_attack IS NULL OR capec_max_likelihood_of_attack IN ('Low','Medium','High')),
  CONSTRAINT dev_issues_capec_max_typical_severity_check CHECK (capec_max_typical_severity IS NULL OR capec_max_typical_severity IN ('Low','Medium','High','Very High'))
);

CREATE INDEX idx_dev_issues_agent_run_id ON dev.issues (agent_run_id);
CREATE INDEX idx_dev_issues_severity ON dev.issues (severity);
CREATE INDEX idx_dev_issues_source ON dev.issues (source);
CREATE INDEX idx_dev_issues_cve_id ON dev.issues (cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_dev_issues_derived_risk ON dev.issues (derived_risk DESC NULLS LAST);
CREATE INDEX idx_dev_issues_first_detected ON dev.issues (first_detected DESC NULLS LAST);
CREATE INDEX idx_dev_issues_priority ON dev.issues (priority) WHERE priority IS NOT NULL;
CREATE INDEX idx_dev_issues_raw_finding_id ON dev.issues (raw_finding_id);
CREATE INDEX idx_dev_issues_cwe_likelihood_of_exploit ON dev.issues (cwe_likelihood_of_exploit) WHERE cwe_likelihood_of_exploit IS NOT NULL;
CREATE INDEX idx_dev_issues_capec_ids_gin ON dev.issues USING gin (capec_ids);
CREATE INDEX idx_dev_issues_attack_technique_ids_gin ON dev.issues USING gin (attack_technique_ids);
CREATE INDEX idx_dev_issues_attack_tactics_gin ON dev.issues USING gin (attack_tactics);
CREATE INDEX idx_dev_issues_attack_platforms_gin ON dev.issues USING gin (attack_platforms);
CREATE INDEX idx_dev_issues_scoring_policy ON dev.issues (scoring_policy_version) WHERE scoring_policy_version IS NOT NULL;
CREATE INDEX idx_dev_issues_runtime_hostname ON dev.issues (runtime_hostname) WHERE runtime_hostname IS NOT NULL;
CREATE INDEX idx_dev_issues_runtime_os_family ON dev.issues (runtime_os_family) WHERE runtime_os_family IS NOT NULL;
CREATE INDEX idx_dev_issues_runtime_purl ON dev.issues (runtime_purl) WHERE runtime_purl IS NOT NULL;


-- =============================================================================
-- 5. connection_registry
-- =============================================================================
CREATE TABLE dev.connection_registry (
  tool           text        NOT NULL,
  protocol       text        NOT NULL,
  auth_type      text        NOT NULL,
  endpoint       text        NOT NULL,
  auth_ref       text        NOT NULL,
  rate_limit_rpm integer,
  timeout_sec    integer     NOT NULL DEFAULT 30,
  metadata       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  enabled        boolean     NOT NULL DEFAULT true,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  last_fetched_at timestamptz,

  CONSTRAINT dev_connection_registry_pkey PRIMARY KEY (tool),
  CONSTRAINT dev_connection_registry_protocol_check CHECK (protocol IN ('REST','MCP','FILE','GRAPHQL'))
);


-- =============================================================================
-- 6. prompt_db
-- =============================================================================
CREATE TABLE dev.prompt_db (
  id          bigserial   NOT NULL,
  agent       text        NOT NULL,
  version     text        NOT NULL,
  model       text        NOT NULL,
  prompt_text text        NOT NULL,
  parameters  jsonb       NOT NULL DEFAULT '{}'::jsonb,
  is_active   boolean     NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_prompt_db_pkey PRIMARY KEY (id),
  CONSTRAINT dev_prompt_db_agent_version_key UNIQUE (agent, version)
);

CREATE INDEX idx_dev_prompt_db_active ON dev.prompt_db (agent) WHERE is_active = true;


-- =============================================================================
-- 7. schema_mapping
-- =============================================================================
CREATE TABLE dev.schema_mapping (
  id              bigserial   NOT NULL,
  scanner         text        NOT NULL,
  source_field    text        NOT NULL,
  canonical_field text        NOT NULL,
  transform       jsonb       NOT NULL DEFAULT '{"type": "direct"}'::jsonb,
  notes           text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_schema_mapping_pkey PRIMARY KEY (id),
  CONSTRAINT dev_schema_mapping_scanner_source_field_canonical_field_key UNIQUE (scanner, source_field, canonical_field)
);

CREATE INDEX idx_dev_schema_mapping_scanner ON dev.schema_mapping (scanner);


-- =============================================================================
-- 8. remediation_patterns
-- =============================================================================
CREATE TABLE dev.remediation_patterns (
  family                text        NOT NULL,
  display_name          text        NOT NULL,
  action_type           text        NOT NULL,
  canonical_steps       jsonb       NOT NULL DEFAULT '[]'::jsonb,
  rollback_strategy     text        NOT NULL,
  rollback_steps        jsonb       NOT NULL DEFAULT '[]'::jsonb,
  validation_tests      jsonb       NOT NULL DEFAULT '[]'::jsonb,
  primary_sources       text[]      NOT NULL DEFAULT '{}'::text[],
  confidence_base       smallint    NOT NULL,
  notes                 text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  test_script_templates jsonb       NOT NULL DEFAULT '[]'::jsonb,

  CONSTRAINT dev_remediation_patterns_pkey PRIMARY KEY (family),
  CONSTRAINT dev_remediation_patterns_action_type_check CHECK (action_type IN ('configuration_change','code_change','package_upgrade','dependency_upgrade','os_patch','container_image_upgrade','secret_rotation','iam_policy_fix','certificate_renewal','network_policy_change','access_removal','service_upgrade')),
  CONSTRAINT dev_remediation_patterns_rollback_strategy_check CHECK (rollback_strategy IN ('automatic','redeploy','manual','not_applicable')),
  CONSTRAINT dev_remediation_patterns_confidence_base_check CHECK (confidence_base >= 0 AND confidence_base <= 100)
);


-- =============================================================================
-- 9. remediation_packages
-- =============================================================================
CREATE TABLE dev.remediation_packages (
  id                        bigserial   NOT NULL,
  issue_id                  bigint      NOT NULL,
  family                    text        NOT NULL,
  finding                   text        NOT NULL,
  root_cause                text        NOT NULL,
  impact                    text        NOT NULL,
  pathways                  jsonb       NOT NULL,
  recommended_pathway_index smallint    NOT NULL DEFAULT 0,
  approval_required         text        NOT NULL,
  status                    text        NOT NULL DEFAULT 'awaiting_approval'::text,
  approved_by               text,
  approved_at               timestamptz,
  rejected_reason           text,
  agent_run_id              uuid,
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_remediation_packages_pkey PRIMARY KEY (id),
  CONSTRAINT dev_remediation_packages_issue_id_fkey FOREIGN KEY (issue_id) REFERENCES dev.issues(id),
  CONSTRAINT dev_remediation_packages_agent_run_id_fkey FOREIGN KEY (agent_run_id) REFERENCES dev.agent_runs(run_id),
  CONSTRAINT dev_remediation_packages_approval_required_check CHECK (approval_required IN ('auto','single_approver','multi_stage')),
  CONSTRAINT dev_remediation_packages_status_check CHECK (status IN ('draft','awaiting_approval','approved','rejected','ready_for_execution')),
  CONSTRAINT dev_remediation_packages_recommended_pathway_index_check CHECK (recommended_pathway_index >= 0)
);

CREATE INDEX idx_dev_remediation_packages_issue_id ON dev.remediation_packages (issue_id);
CREATE INDEX idx_dev_remediation_packages_run_id ON dev.remediation_packages (agent_run_id) WHERE agent_run_id IS NOT NULL;
CREATE INDEX idx_dev_remediation_packages_status ON dev.remediation_packages (status);
CREATE INDEX idx_dev_remediation_packages_created_at ON dev.remediation_packages (created_at DESC);


-- =============================================================================
-- 10. fix_runs
-- =============================================================================
CREATE TABLE dev.fix_runs (
  id                    bigserial   NOT NULL,
  package_id            bigint      NOT NULL,
  issue_id              bigint      NOT NULL,
  pathway_index         integer     NOT NULL DEFAULT 0,
  agent_run_id          uuid        NOT NULL,
  status                text        NOT NULL DEFAULT 'pending'::text,
  environment           text        NOT NULL DEFAULT 'sandbox'::text,
  target_instance_id    text,
  target_file_path      text,
  working_directory     text,
  strategy              text        NOT NULL,
  step_results          jsonb       NOT NULL DEFAULT '[]'::jsonb,
  validation_results    jsonb       NOT NULL DEFAULT '[]'::jsonb,
  terraform_plan_output text,
  rollback_triggered    boolean     NOT NULL DEFAULT false,
  rollback_results      jsonb       NOT NULL DEFAULT '[]'::jsonb,
  backup_reference      text,
  prod_fix_run_id       bigint,
  started_at            timestamptz,
  finished_at           timestamptz,
  duration_seconds      integer,
  error_message         text,
  error_step_number     integer,
  timeout_seconds       integer     NOT NULL DEFAULT 300,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_fix_runs_pkey PRIMARY KEY (id),
  CONSTRAINT dev_fix_runs_issue_id_fkey FOREIGN KEY (issue_id) REFERENCES dev.issues(id),
  CONSTRAINT dev_fix_runs_package_id_fkey FOREIGN KEY (package_id) REFERENCES dev.remediation_packages(id),
  CONSTRAINT dev_fix_runs_prod_fix_run_id_fkey FOREIGN KEY (prod_fix_run_id) REFERENCES dev.fix_runs(id),
  CONSTRAINT dev_fix_runs_status_check CHECK (status IN ('pending','provisioning','executing','validating','success','failed','rolled_back','promoted')),
  CONSTRAINT dev_fix_runs_environment_check CHECK (environment IN ('sandbox','production')),
  CONSTRAINT dev_fix_runs_strategy_check CHECK (strategy IN ('iac','cli','dependency','code_edit'))
);

CREATE INDEX idx_dev_fix_runs_agent_run_id ON dev.fix_runs (agent_run_id);
CREATE INDEX idx_dev_fix_runs_issue_id ON dev.fix_runs (issue_id);
CREATE INDEX idx_dev_fix_runs_package_id ON dev.fix_runs (package_id);
CREATE INDEX idx_dev_fix_runs_status ON dev.fix_runs (status);
CREATE INDEX idx_dev_fix_runs_created_at ON dev.fix_runs (created_at DESC);


-- =============================================================================
-- 11. assets
-- =============================================================================
CREATE TABLE dev.assets (
  asset_id             text        NOT NULL,
  hostname             text,
  ip_address           text,
  asset_type           text,
  environment          text,
  business_owner       text,
  contact_email        text,
  name                 text        NOT NULL,
  aliases              text[]      NOT NULL DEFAULT '{}'::text[],
  application_name     text,
  description          text,
  repo_url             text,
  exposure             text,
  business_criticality smallint,
  data_classification  text,
  compliance_tags      text[]      NOT NULL DEFAULT '{}'::text[],
  owner_team           text,
  last_seen_at         timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  network_zone         text,
  dependencies         jsonb       NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT dev_assets_pkey PRIMARY KEY (asset_id),
  CONSTRAINT dev_assets_name_key UNIQUE (name),
  CONSTRAINT dev_assets_asset_type_check CHECK (asset_type IN ('application','service','repository','package','infrastructure')),
  CONSTRAINT dev_assets_environment_check CHECK (environment IN ('production','staging','development','qa','sandbox')),
  CONSTRAINT dev_assets_exposure_check CHECK (exposure IN ('public','internal')),
  CONSTRAINT dev_assets_business_criticality_check CHECK (business_criticality >= 1 AND business_criticality <= 5),
  CONSTRAINT dev_assets_data_classification_check CHECK (data_classification IN ('public','internal','confidential','restricted')),
  CONSTRAINT dev_assets_network_zone_check CHECK (network_zone IS NULL OR network_zone IN ('internet','extranet','intranet'))
);

CREATE INDEX idx_dev_assets_aliases_gin ON dev.assets USING gin (aliases);
CREATE INDEX idx_dev_assets_compliance_gin ON dev.assets USING gin (compliance_tags);
CREATE INDEX idx_dev_assets_criticality ON dev.assets (business_criticality DESC NULLS LAST);
CREATE INDEX idx_dev_assets_dependencies ON dev.assets USING gin (dependencies);
CREATE INDEX idx_dev_assets_environment ON dev.assets (environment);
CREATE INDEX idx_dev_assets_exposure ON dev.assets (exposure);
CREATE INDEX idx_dev_assets_hostname ON dev.assets (hostname) WHERE hostname IS NOT NULL;
CREATE INDEX idx_dev_assets_ip_address ON dev.assets (ip_address) WHERE ip_address IS NOT NULL;
CREATE INDEX idx_dev_assets_network_zone ON dev.assets (network_zone) WHERE network_zone IS NOT NULL;


-- =============================================================================
-- 12. monitored_packages
-- =============================================================================
CREATE TABLE dev.monitored_packages (
  id         bigserial   NOT NULL,
  ecosystem  text        NOT NULL,
  name       text        NOT NULL,
  version    text        NOT NULL,
  label      text,
  enabled    boolean     NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_monitored_packages_pkey PRIMARY KEY (id),
  CONSTRAINT dev_monitored_packages_ecosystem_name_version_key UNIQUE (ecosystem, name, version)
);


-- =============================================================================
-- 13. mitre_cwe
-- =============================================================================
CREATE TABLE dev.mitre_cwe (
  cwe_id               text        NOT NULL,
  name                 text        NOT NULL,
  abstraction          text,
  status               text,
  description          text,
  extended_description text,
  likelihood_of_exploit text,
  consequences         jsonb       NOT NULL DEFAULT '[]'::jsonb,
  mitigations          jsonb       NOT NULL DEFAULT '[]'::jsonb,
  related_capec        text[]      NOT NULL DEFAULT '{}'::text[],
  mitre_version        text,
  fetched_at           timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_mitre_cwe_pkey PRIMARY KEY (cwe_id)
);

CREATE INDEX idx_dev_mitre_cwe_name ON dev.mitre_cwe (name);


-- =============================================================================
-- 14. mitre_capec
-- =============================================================================
CREATE TABLE dev.mitre_capec (
  capec_id                  text        NOT NULL,
  name                      text        NOT NULL,
  abstraction               text,
  status                    text,
  description               text,
  likelihood_of_attack      text,
  typical_severity          text,
  execution_flow            jsonb       NOT NULL DEFAULT '[]'::jsonb,
  prerequisites             text[]      NOT NULL DEFAULT '{}'::text[],
  skills_required           jsonb       NOT NULL DEFAULT '[]'::jsonb,
  resources_required        text,
  consequences              jsonb       NOT NULL DEFAULT '[]'::jsonb,
  mitigations               text[]      NOT NULL DEFAULT '{}'::text[],
  related_weaknesses        text[]      NOT NULL DEFAULT '{}'::text[],
  related_attack_techniques text[]      NOT NULL DEFAULT '{}'::text[],
  mitre_version             text,
  fetched_at                timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_mitre_capec_pkey PRIMARY KEY (capec_id)
);

CREATE INDEX idx_dev_mitre_capec_name ON dev.mitre_capec (name);


-- =============================================================================
-- 15. mitre_attack_techniques
-- =============================================================================
CREATE TABLE dev.mitre_attack_techniques (
  technique_id        text        NOT NULL,
  name                text        NOT NULL,
  description         text,
  tactics             text[]      NOT NULL DEFAULT '{}'::text[],
  is_subtechnique     boolean     NOT NULL DEFAULT false,
  parent_technique_id text,
  platforms           text[]      NOT NULL DEFAULT '{}'::text[],
  data_sources        text[]      NOT NULL DEFAULT '{}'::text[],
  detection           text,
  url                 text,
  mitre_version       text,
  fetched_at          timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_mitre_attack_techniques_pkey PRIMARY KEY (technique_id)
);

CREATE INDEX idx_dev_mitre_attack_name ON dev.mitre_attack_techniques (name);
CREATE INDEX idx_dev_mitre_attack_parent ON dev.mitre_attack_techniques (parent_technique_id) WHERE parent_technique_id IS NOT NULL;


-- =============================================================================
-- 16. mitre_refresh_log
-- =============================================================================
CREATE TABLE dev.mitre_refresh_log (
  id              bigserial   NOT NULL,
  source          text        NOT NULL,
  sha256          text        NOT NULL,
  status          text        NOT NULL,
  cwes_processed  integer,
  mitre_version   text,
  error_message   text,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT dev_mitre_refresh_log_pkey PRIMARY KEY (id),
  CONSTRAINT dev_mitre_refresh_log_source_check CHECK (source IN ('cwe','capec','attack')),
  CONSTRAINT dev_mitre_refresh_log_status_check CHECK (status IN ('unchanged','updated','failed'))
);

CREATE INDEX idx_dev_mitre_refresh_log_source_time ON dev.mitre_refresh_log (source, created_at DESC);


-- =============================================================================
-- RLS — Enable but allow service_role full access (same as public schema)
-- =============================================================================
ALTER TABLE dev.agent_runs              ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.agent_trace_events      ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.raw_findings            ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.issues                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.connection_registry     ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.prompt_db               ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.schema_mapping          ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.remediation_patterns    ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.remediation_packages    ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.fix_runs                ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.assets                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.monitored_packages      ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.mitre_cwe               ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.mitre_capec             ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.mitre_attack_techniques ENABLE ROW LEVEL SECURITY;
ALTER TABLE dev.mitre_refresh_log       ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS by default in Supabase, so no explicit policies
-- needed for backend writes. Add read policies for authenticated if you
-- need frontend/realtime access to dev schema later.


-- =============================================================================
-- SEED — Copy data from public into dev (run once after creating schema)
-- =============================================================================
-- Uncomment and run the block below to seed dev tables with current prod data.
-- This is safe to run multiple times (uses INSERT which will fail on PK
-- conflicts — or use INSERT ... ON CONFLICT DO NOTHING for idempotency).

/*
INSERT INTO dev.connection_registry     SELECT * FROM public.connection_registry;
INSERT INTO dev.prompt_db               SELECT * FROM public.prompt_db;
INSERT INTO dev.schema_mapping          SELECT * FROM public.schema_mapping;
INSERT INTO dev.remediation_patterns    SELECT * FROM public.remediation_patterns;
INSERT INTO dev.assets                  SELECT * FROM public.assets;
INSERT INTO dev.monitored_packages      SELECT * FROM public.monitored_packages;
INSERT INTO dev.mitre_cwe               SELECT * FROM public.mitre_cwe;
INSERT INTO dev.mitre_capec             SELECT * FROM public.mitre_capec;
INSERT INTO dev.mitre_attack_techniques SELECT * FROM public.mitre_attack_techniques;
INSERT INTO dev.mitre_refresh_log       SELECT * FROM public.mitre_refresh_log;
*/
