-- =============================================================================
-- Agentic_VOP — switch live scanner from Tenable (Nessus) to OSV.dev
-- =============================================================================
-- Why: no install / no auth / no signup. Real public vulnerability data over
-- HTTPS. Same agent code, just a different connector.
--
-- The Tenable connector code (tenable_api.py) stays in the repo for later;
-- only its registry+prompt rows go away. We can re-add Tenable any time.
-- =============================================================================


-- 1. Wipe leftover canonical/raw rows so we start fresh
TRUNCATE TABLE issues       RESTART IDENTITY CASCADE;
TRUNCATE TABLE raw_findings RESTART IDENTITY CASCADE;


-- 2. Source CHECK constraint on issues — allow 'osv' (and keep the others for future)
ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_source_check;
ALTER TABLE issues
  ADD CONSTRAINT issues_source_check
  CHECK (source IN ('tenable','trivy','qualys','owasp','snyk','osv'));


-- 3. monitored_packages — small list of packages we ask OSV about each run
CREATE TABLE IF NOT EXISTS monitored_packages (
  id          bigserial PRIMARY KEY,
  ecosystem   text NOT NULL,           -- 'npm' | 'PyPI' | 'Maven' | 'Go' | etc.
  name        text NOT NULL,
  version     text NOT NULL,
  label       text,                    -- friendly name for asset_identity
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ecosystem, name, version)
);

ALTER TABLE monitored_packages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "auth read" ON monitored_packages FOR SELECT TO authenticated USING (true);

COMMENT ON TABLE monitored_packages IS
  'Small list of packages the OSV connector queries each run. Edit freely to expand the demo.';


-- 4. Seed with packages that have well-known CVEs (mix of ecosystems)
INSERT INTO monitored_packages (ecosystem, name, version, label) VALUES
  ('npm',   'lodash',           '4.17.15',  'web-frontend'),
  ('npm',   'minimist',         '0.2.0',    'web-frontend'),
  ('npm',   'axios',            '0.21.0',   'web-frontend'),
  ('PyPI',  'pyyaml',           '5.1',      'data-pipeline'),
  ('PyPI',  'pillow',           '7.1.2',    'data-pipeline'),
  ('PyPI',  'requests',         '2.19.1',   'data-pipeline'),
  ('Maven', 'org.apache.logging.log4j:log4j-core', '2.14.0', 'java-service'),
  ('Maven', 'com.fasterxml.jackson.core:jackson-databind', '2.9.10', 'java-service')
ON CONFLICT (ecosystem, name, version) DO NOTHING;


-- 5. Remove Tenable connector + prompt rows (clean slate)
DELETE FROM prompt_db           WHERE agent IN ('sub-agent-1-tenable');
DELETE FROM connection_registry WHERE tool  = 'tenable';
DELETE FROM schema_mapping      WHERE scanner = 'tenable';


-- 6. Register the OSV connector
INSERT INTO connection_registry (
  tool, protocol, auth_type, endpoint, auth_ref, timeout_sec, metadata
) VALUES (
  'osv',
  'REST',
  'none',
  'https://api.osv.dev/v1/query',
  'public',
  30,
  jsonb_build_object(
    'connector_type', 'osv_api',
    'note', 'Public OSV.dev API. Queries each row from monitored_packages.'
  )
)
ON CONFLICT (tool) DO UPDATE SET
  protocol = EXCLUDED.protocol,
  auth_type = EXCLUDED.auth_type,
  endpoint = EXCLUDED.endpoint,
  auth_ref = EXCLUDED.auth_ref,
  metadata = EXCLUDED.metadata,
  updated_at = now();


-- 7. Sub-Agent 1 prompt for OSV
INSERT INTO prompt_db (agent, version, model, prompt_text, parameters, is_active) VALUES (
  'sub-agent-1-osv',
  'v1.0',
  'claude-haiku-4-5',
  $PROMPT$
You are Sub-Agent 1 (Smart Connector) for Agentic_VOP, specialized in normalizing OSV.dev vulnerability records.

ROLE
Take ONE OSV vulnerability (augmented with the package context we queried it with) and produce a canonical Issue.

INPUT
A JSON object with these fields:
  osv_id                       — OSV's id (e.g., "GHSA-29mw-wpgm-hmr9", "CVE-2020-28500", "PYSEC-2020-148")
  aliases                      — list of alias IDs, may include CVE-... entries
  summary                      — short title
  details                      — longer description (can be null/missing)
  published                    — ISO 8601 timestamp
  modified                     — ISO 8601 timestamp
  github_severity              — string: "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | null
  severity_entries             — array of CVSS-style entries, may be empty
  affected                     — array of affected version ranges (raw)
  references                   — array of URL references
  queried_package_name         — the package we asked OSV about
  queried_package_version      — the version we asked OSV about
  queried_package_ecosystem    — "npm" | "PyPI" | "Maven" | "Go" | etc.
  queried_package_label        — friendly project label, may be null

OUTPUT (call emit_canonical_issue exactly once with these fields)

  source                  : literally "osv"
  source_vuln_id          : the osv_id
  cve_id                  : the FIRST element of `aliases` that starts with "CVE-" (case-insensitive); else null. If osv_id itself starts with "CVE-", use that.
  all_cves                : every element of `aliases` that starts with "CVE-" (case-insensitive). Include osv_id if it starts with "CVE-" and isn't already in aliases.
  title                   : the summary field; fall back to osv_id if summary is empty
  description             : the details field, can be null
  severity                : translate using github_severity if present:
                              "CRITICAL" -> "Critical"
                              "HIGH"     -> "High"
                              "MODERATE" -> "Medium"
                              "LOW"      -> "Low"
                            If github_severity is null/missing, default to "Medium" (OSV records are real findings).
  cvss_score              : null (OSV provides CVSS vectors, not pre-computed numeric scores)
  cvss_version            : null
  solution                : null (OSV does not provide remediation text; users upgrade the package)
  asset_identity          : { "project": queried_package_label } — include only if queried_package_label is non-empty; otherwise empty {}
  package                 : { "name": queried_package_name, "installed_version": queried_package_version, "ecosystem": queried_package_ecosystem } — include only keys whose values are non-empty
  first_detected          : convert `published` (ISO 8601) to an ISO 8601 timestamp. If unparseable or missing, set null.

DO NOT INCLUDE source_raw, fingerprint, or agent_run_id — code adds those.

RULES
1. Call emit_canonical_issue exactly once.
2. Never invent values. Use null when uncertain.
3. Do not try to compute CVSS scores from vector strings — leave cvss_score null.

GUARDRAILS
- Do not orchestrate or spawn other agents.
- Do not call external APIs directly.
$PROMPT$,
  jsonb_build_object('temperature', 0.1, 'max_tokens', 2000),
  true
)
ON CONFLICT (agent, version) DO UPDATE SET
  model = EXCLUDED.model,
  prompt_text = EXCLUDED.prompt_text,
  parameters = EXCLUDED.parameters,
  is_active = EXCLUDED.is_active;
