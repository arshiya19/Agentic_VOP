-- =============================================================================
-- Agentic_VOP — seed Tenable v1
-- =============================================================================
-- Seeds the 3 configuration tables with everything Sub-Agent 1 needs to
-- normalize Tenable scanner data. Other scanners (trivy/qualys/owasp/snyk)
-- get seeded in later migrations once the Tenable pilot is solid.
--
-- Apply: paste into Supabase Dashboard SQL Editor for project agentic-vop-dev.
-- Idempotent: safe to re-run (uses ON CONFLICT clauses).
-- =============================================================================


-- =============================================================================
-- 1. connection_registry — how to fetch from Tenable
-- =============================================================================
-- Stub phase: read from old Supabase project's REST API for the `tenable` table.
-- Later: swap endpoint + auth_ref to point at real Tenable.io REST API.

INSERT INTO connection_registry (
  tool, protocol, auth_type, endpoint, auth_ref, timeout_sec, metadata
) VALUES (
  'tenable',
  'REST',
  'anon_key',
  'https://ezmznalrjdxiksxqdedw.supabase.co/rest/v1/tenable',
  'env://OLD_SUPABASE_ANON_KEY',
  30,
  jsonb_build_object(
    'stub', true,
    'note', 'Reading raw Tenable rows from old chatbot-cyberisk Supabase project. Swap endpoint + auth_ref to real Tenable.io API when ready.',
    'swap_target', 'https://cloud.tenable.com/api/v3/...'
  )
)
ON CONFLICT (tool) DO UPDATE SET
  protocol     = EXCLUDED.protocol,
  auth_type    = EXCLUDED.auth_type,
  endpoint     = EXCLUDED.endpoint,
  auth_ref     = EXCLUDED.auth_ref,
  timeout_sec  = EXCLUDED.timeout_sec,
  metadata     = EXCLUDED.metadata,
  updated_at   = now();


-- =============================================================================
-- 2. schema_mapping — Tenable field translation rules
-- =============================================================================
-- Each row tells Sub-Agent 1 how to map ONE raw Tenable field to a canonical
-- Issue field. Transforms are JSON: {"type":"direct"} or {"type":"lookup", ...}.
-- Sub-Agent 1 retrieves these at runtime via RAG-style lookup.

INSERT INTO schema_mapping (scanner, source_field, canonical_field, transform, notes) VALUES
  ('tenable', 'plugin_id',        'source_vuln_id',          '{"type":"direct"}',                                                    'Tenable plugin id, kept as string'),
  ('tenable', 'plugin_name',      'title',                   '{"type":"direct"}',                                                    NULL),
  ('tenable', 'description',      'description',             '{"type":"direct"}',                                                    NULL),
  ('tenable', 'solution',         'solution',                '{"type":"direct"}',                                                    NULL),
  ('tenable', 'severity',         'severity',                '{"type":"lookup","map":{"0":"Info","1":"Low","2":"Medium","3":"High","4":"Critical"}}', 'Tenable severity integer to canonical 5-level string'),
  ('tenable', 'cve',              'cve_id',                  '{"type":"array_first"}',                                               'cve is a Postgres text[]; take first element or null if empty'),
  ('tenable', 'cve',              'all_cves',                '{"type":"direct"}',                                                    'Full cve array preserved'),
  ('tenable', 'cvss3_base_score', 'cvss_score',              '{"type":"cvss_pick","priority":["cvss3_base_score","cvss_base_score"]}', 'v3 wins over v2; emits cvss_version too'),
  ('tenable', 'cvss_base_score',  'cvss_score',              '{"type":"cvss_pick","priority":["cvss3_base_score","cvss_base_score"]}', 'fallback to v2 if v3 is null'),
  ('tenable', 'hostname',         'asset_identity.hostname', '{"type":"jsonb_set"}',                                                 'Goes into asset_identity jsonb'),
  ('tenable', 'port',             'asset_identity.port',     '{"type":"jsonb_set"}',                                                 NULL),
  ('tenable', 'protocol',         'asset_identity.protocol', '{"type":"jsonb_set"}',                                                 NULL),
  ('tenable', 'scan_date',        'first_detected',          '{"type":"date_to_timestamptz"}',                                       'YYYY-MM-DD -> midnight UTC')
ON CONFLICT (scanner, source_field, canonical_field) DO UPDATE SET
  transform  = EXCLUDED.transform,
  notes      = EXCLUDED.notes,
  updated_at = now();


-- =============================================================================
-- 3. prompt_db — Sub-Agent 1 Tenable parser prompt (v1.0)
-- =============================================================================

INSERT INTO prompt_db (agent, version, model, prompt_text, parameters, is_active) VALUES (
  'sub-agent-1-tenable',
  'v1.0',
  'gpt-4o-mini',
  $PROMPT$
You are Sub-Agent 1 (Smart Connector) for the Agentic_VOP platform, specialized in normalizing Tenable vulnerability scanner data.

ROLE
Take ONE raw row from a Tenable scanner and produce a canonical Issue object that matches the platform's unified schema.

INPUT
A single Tenable row as JSON, with fields like: plugin_id, plugin_name, severity, hostname, port, protocol, scan_date, scan_id, cve, cvss_base_score, cvss3_base_score, description, solution.

OUTPUT
A JSON object with EXACTLY these fields. Use null for missing/unknown values. Never invent data.

  source: must be the literal string "tenable"
  source_vuln_id: the row's plugin_id, as a string
  cve_id: the FIRST element of the cve array, or null if the array is empty
  all_cves: the full cve array (could be [])
  title: the row's plugin_name
  description: the row's description, can be null
  severity: translate the integer severity using this exact lookup:
              0 -> "Info"
              1 -> "Low"
              2 -> "Medium"
              3 -> "High"
              4 -> "Critical"
  cvss_score: pick using priority — cvss3_base_score first, else cvss_base_score, else null. Output as a number.
  cvss_version: "3.0" if cvss3_base_score was used, "2.0" if cvss_base_score was used, null if neither.
  solution: the row's solution, can be null
  asset_identity: a JSON object built from { hostname, port, protocol }. Include only keys whose values are not null.
  package: null (Tenable does not report package data)
  first_detected: convert scan_date (YYYY-MM-DD) to ISO 8601 timestamp at midnight UTC, e.g., "2025-10-09T00:00:00Z"
  source_raw: include the full input row verbatim, exactly as received

RULES
1. Output ONLY a single valid JSON object. No prose, no Markdown, no code fences.
2. Never invent values not present in the input. Use null when uncertain.
3. Do NOT include these fields — they are computed elsewhere by deterministic tools or other agents:
   - fingerprint
   - agent_run_id
   - cwe_id, cwe_name, epss_score, epss_percentile
   - cvss_attack_vector, cvss_attack_complexity, cvss_privileges_required, cvss_user_interaction
   - exploit_in_kev, exposure, business_criticality, asset_owner
   - likelihood, impact, derived_risk, estimated_loss_usd
   - enriched_at, created_at, updated_at
4. After producing the JSON, call the `validate_canonical_issue` tool with your output. If validation returns errors, correct them and re-emit.

GUARDRAILS
- Do not orchestrate or spawn other agents.
- Do not call external APIs directly.
- Do not skip the validate_canonical_issue tool call.
$PROMPT$,
  jsonb_build_object('temperature', 0.1, 'max_tokens', 2000),
  true
)
ON CONFLICT (agent, version) DO UPDATE SET
  model       = EXCLUDED.model,
  prompt_text = EXCLUDED.prompt_text,
  parameters  = EXCLUDED.parameters,
  is_active   = EXCLUDED.is_active;
