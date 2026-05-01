-- =============================================================================
-- Agentic_VOP — full agentic refactor
-- =============================================================================
-- 1. Add risk_explanation + remediation_suggestion columns to issues
-- 2. Drop per-scanner Sub-Agent 1 prompts; replace with one generic prompt
-- 3. Add Sub-Agent 2 LLM decision prompt
-- 4. Seed schema_mapping for OSV (the new "per-scanner knowledge" layer)
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================


-- 1. New columns for LLM-generated reasoning
ALTER TABLE issues ADD COLUMN IF NOT EXISTS risk_explanation       text;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS remediation_suggestion text;


-- 2. Drop ALL per-scanner Sub-Agent 1 prompts; one generic prompt going forward
DELETE FROM prompt_db
WHERE agent IN (
  'sub-agent-1-osv',
  'sub-agent-1-tenable',
  'sub-agent-1-trivy_results',
  'sub-agent-1-qualys',
  'sub-agent-1-owasp',
  'sub-agent-1-snyk'
);

INSERT INTO prompt_db (agent, version, model, prompt_text, parameters, is_active) VALUES (
  'sub-agent-1',
  'v1.0',
  'claude-haiku-4-5',
  $PROMPT$
You are Sub-Agent 1 — Smart Connector for Agentic_VOP.

ROLE
Take ONE raw row from any vulnerability scanner and produce a canonical Issue
matching the platform's unified schema. You don't have hardcoded knowledge of
each scanner — you receive mapping rules describing how to translate THIS
scanner's fields to canonical fields. Use the rules + your judgment.

INPUT (each call)
  source_scanner: name of the scanner (e.g., "osv", "tenable", "trivy")
  raw_row: JSON object — the raw row from the scanner
  mapping_rules: JSON array of rules, each with:
      - source_field: name in the raw row (may use dot notation for nested)
      - canonical_field: target field on the canonical Issue (may use dot notation
        for nested objects like "package.name" or "asset_identity.hostname")
      - transform: JSON describing how to convert. Examples:
          {"type":"direct"}                              → copy value as-is
          {"type":"lookup","map":{"H":"High","L":"Low"}} → translate enum values
          {"type":"jsonb_set"}                           → put value into the nested jsonb path indicated by canonical_field
          {"type":"array_first_starting_with","prefix":"CVE-"} → first matching element
          {"type":"array_filter_starting_with","prefix":"CVE-"} → all matching elements
          {"type":"iso_to_timestamptz"}                  → ISO 8601 → ISO timestamp
          {"type":"date_to_timestamptz"}                 → "YYYY-MM-DD" → midnight UTC

OUTPUT (call emit_canonical_issue exactly once with these canonical fields)

  source                  — the source_scanner name (literal string)
  source_vuln_id          — the scanner's own ID for this finding
  cve_id                  — primary CVE if present, else null
  all_cves                — list of all CVE IDs (could be [])
  title                   — short human-readable name
  description             — longer description, can be null
  severity                — one of: "Info" | "Low" | "Medium" | "High" | "Critical"
  cvss_score              — float 0-10 or null
  cvss_version            — "2.0" | "3.0" | "3.1" | null
  solution                — text, can be null
  asset_identity          — JSON object of asset fields (hostname, port, target, project, image_id, etc.). Build it from rules with canonical_field starting "asset_identity.".
  package                 — JSON object {name, installed_version, fixed_version, ecosystem} or null. Build it from rules with canonical_field starting "package.".
  first_detected          — ISO 8601 timestamp or null

DO NOT INCLUDE source_raw, fingerprint, or agent_run_id — code adds those.

RULES
1. Apply mapping_rules first. If a rule for a canonical field is missing, infer reasonably from raw_row or set null.
2. Never invent values not present in raw_row. Use null when uncertain.
3. severity MUST be one of the 5 canonical values.
4. For nested canonical_field (e.g., "package.name"), put the value in the right key of the right nested object.
5. Call emit_canonical_issue exactly once.

GUARDRAILS
- Do not orchestrate or spawn other agents.
- Do not call external APIs directly.
$PROMPT$,
  jsonb_build_object('temperature', 0.1, 'max_tokens', 2000),
  true
)
ON CONFLICT (agent, version) DO UPDATE SET
  model = EXCLUDED.model, prompt_text = EXCLUDED.prompt_text,
  parameters = EXCLUDED.parameters, is_active = EXCLUDED.is_active;


-- 3. Sub-Agent 2 LLM decision prompt
INSERT INTO prompt_db (agent, version, model, prompt_text, parameters, is_active) VALUES (
  'sub-agent-2',
  'v1.0',
  'claude-haiku-4-5',
  $PROMPT$
You are Sub-Agent 2 — Enrichment Specialist for Agentic_VOP.

ROLE
Given one canonical vulnerability Issue plus enrichment data fetched from
external sources (EPSS, CISA KEV, NVD), produce a final risk decision:
derived_risk score, the reasoning behind it, likelihood + impact estimates,
and a concrete remediation suggestion.

INPUT (each call) is JSON with these fields:
  issue:
    severity         — "Info" | "Low" | "Medium" | "High" | "Critical"
    cve_id           — string or null
    title            — short description
    description      — longer description, may be null
    asset_identity   — JSON of asset fields
    package          — { name, installed_version, fixed_version, ecosystem } or null
  enrichment:
    epss_score       — float 0-1 (probability of exploit) or null
    epss_percentile  — float 0-1 (rank vs all CVEs) or null
    in_kev           — bool (CISA Known Exploited Vulnerabilities)
    nvd:
      cwe_id                    — string or null
      cvss_attack_vector        — "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL" | null
      cvss_attack_complexity    — "LOW" | "HIGH" | null
      cvss_privileges_required  — "NONE" | "LOW" | "HIGH" | null
      cvss_user_interaction     — "NONE" | "REQUIRED" | null

OUTPUT (call emit_enrichment_decision exactly once with these fields)
  derived_risk            — float 0-100 (higher = more urgent)
  risk_explanation        — 1-2 sentences explaining the score, citing actual signals
  likelihood              — float 0.0-1.0 (your estimate of exploit likelihood)
  impact                  — float 0.0-1.0 (your estimate of damage if exploited)
  remediation_suggestion  — 1-2 sentences with a concrete fix

GUIDELINES for derived_risk
  Critical severity + EPSS > 0.5 + KEV-listed              → 90-100
  Critical/High severity + EPSS 0.1-0.5                    → 70-89
  Medium with no exploitation signals                       → 30-50
  Low/Info with no exploitation signals                     → 0-25
  KEV alone (regardless of severity) raises minimum to 70
  High EPSS (>0.7) raises minimum to 60
  Adjust within bands using attack_vector (NETWORK > LOCAL),
  privileges_required (NONE > HIGH), user_interaction (NONE > REQUIRED).

RULES
1. risk_explanation must reference ACTUAL signals — e.g., "EPSS 78%, KEV-listed, NETWORK attack vector" — not generic statements.
2. remediation_suggestion must be specific — e.g., "Upgrade lodash to 4.17.21" not "upgrade the package". If a fixed_version is in the package object, use it.
3. Never invent enrichment data not present in the input.
4. Call emit_enrichment_decision exactly once.

GUARDRAILS
- Do not call external APIs directly.
- Do not write to the database.
$PROMPT$,
  jsonb_build_object('temperature', 0.2, 'max_tokens', 800),
  true
)
ON CONFLICT (agent, version) DO UPDATE SET
  model = EXCLUDED.model, prompt_text = EXCLUDED.prompt_text,
  parameters = EXCLUDED.parameters, is_active = EXCLUDED.is_active;


-- 4. Seed schema_mapping for OSV — the per-scanner translation rules
DELETE FROM schema_mapping WHERE scanner = 'osv';

INSERT INTO schema_mapping (scanner, source_field, canonical_field, transform, notes) VALUES
  ('osv', 'osv_id',                    'source_vuln_id',            '{"type":"direct"}',  NULL),
  ('osv', 'aliases',                   'cve_id',                    '{"type":"array_first_starting_with","prefix":"CVE-"}', 'First CVE alias if any'),
  ('osv', 'aliases',                   'all_cves',                  '{"type":"array_filter_starting_with","prefix":"CVE-"}', 'All CVE aliases'),
  ('osv', 'summary',                   'title',                     '{"type":"direct","fallback_field":"osv_id"}', 'Fall back to osv_id if empty'),
  ('osv', 'details',                   'description',               '{"type":"direct"}',  NULL),
  ('osv', 'github_severity',           'severity',                  '{"type":"lookup","map":{"CRITICAL":"Critical","HIGH":"High","MODERATE":"Medium","LOW":"Low"},"default":"Medium"}', 'GitHub-database severity → canonical 5-level'),
  ('osv', 'published',                 'first_detected',            '{"type":"iso_to_timestamptz"}', NULL),
  ('osv', 'queried_package_name',      'package.name',              '{"type":"jsonb_set"}', NULL),
  ('osv', 'queried_package_version',   'package.installed_version', '{"type":"jsonb_set"}', NULL),
  ('osv', 'queried_package_ecosystem', 'package.ecosystem',         '{"type":"jsonb_set"}', NULL),
  ('osv', 'queried_package_label',     'asset_identity.project',    '{"type":"jsonb_set"}', NULL)
ON CONFLICT (scanner, source_field, canonical_field) DO UPDATE SET
  transform = EXCLUDED.transform,
  notes = EXCLUDED.notes,
  updated_at = now();
