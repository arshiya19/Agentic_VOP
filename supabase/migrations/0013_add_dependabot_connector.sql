-- =============================================================================
-- Agentic_VOP — add GitHub Dependabot connector
-- =============================================================================
-- Registers Dependabot as a live scanner using the GitHub REST API.
-- Requires GITHUB_TOKEN in apps/api/.env.
-- The target account/org is configured via the endpoint URL in the UI —
-- no hardcoded username or org name anywhere in this migration.
--
-- What this migration does:
--   1. Extend the issues.source CHECK constraint to allow 'dependabot'
--   2. Register the connector in connection_registry
--   3. Seed schema_mapping rules for Dependabot's alert shape
--
-- Idempotent: safe to re-run (uses ON CONFLICT / IF NOT EXISTS).
-- =============================================================================

-- Requires GITHUB_TOKEN (ghp_... personal token or a GitHub App installation
-- token with the 'security_events' scope) in apps/api/.env.

-- =============================================================================
-- 1. Extend issues.source CHECK constraint
-- =============================================================================
-- The current constraint was set in 0010. We drop and recreate it to add
-- 'dependabot'. All existing values are preserved.

-- structure for the REST API endpoint should be https://api.github.com/users/{your-username}/repos

ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_source_check;

ALTER TABLE issues
  ADD CONSTRAINT issues_source_check
  CHECK (source IN (
    'tenable',
    'trivy',
    'trivy-cloud',
    'qualys',
    'owasp',
    'snyk',
    'osv',
    'semgrep-appsec',
    'dependabot'
  ));


-- =============================================================================
-- 2. connection_registry — how to reach GitHub Dependabot
-- =============================================================================
-- The connector reads GITHUB_TOKEN from the environment at runtime (config.py).
-- The endpoint is the full GitHub repos list URL for the target account.
-- The connector uses this URL directly to list repos, then derives the API
-- base URL (scheme + host) from it to build per-repo alert URLs.
--
-- Examples:
--   Personal account : https://api.github.com/users/{username}/repos
--   Organisation     : https://api.github.com/orgs/{orgname}/repos
--
-- To change the target, update the endpoint via the UI or PATCH
-- /admin/scanners/dependabot — no metadata fields need to change.

INSERT INTO connection_registry (
  tool, protocol, auth_type, endpoint, auth_ref, timeout_sec, enabled, metadata
) VALUES (
  'dependabot',
  'REST',
  'bearer_token',
  'https://api.github.com/users/{your-username}/repos',
  'env://GITHUB_TOKEN',
  60,
  true,
  jsonb_build_object(
    'connector_type',  'dependabot_api',
    'repo_limit',      50,
    'per_page',        100,
    'note',            'GitHub Dependabot alerts via REST API v3. Set endpoint to the full repos list URL for your account or org.'
  )
)
ON CONFLICT (tool) DO UPDATE SET
  protocol    = EXCLUDED.protocol,
  auth_type   = EXCLUDED.auth_type,
  -- Do NOT overwrite endpoint — preserve whatever the user set via the UI.
  -- To reset the endpoint, use PATCH /admin/scanners/dependabot.
  auth_ref    = EXCLUDED.auth_ref,
  timeout_sec = EXCLUDED.timeout_sec,
  enabled     = EXCLUDED.enabled,
  metadata    = connection_registry.metadata || EXCLUDED.metadata,
  updated_at  = now();


-- =============================================================================
-- 3. schema_mapping — Dependabot alert field translation rules
-- =============================================================================
-- These rules are loaded by Sub-Agent 1 at runtime and passed to the LLM
-- alongside the raw alert row. The LLM uses them to produce a canonical Issue.
--
-- Raw Dependabot alert shape (one row per alert):
--   number                                          — alert number (int)
--   state                                           — "open" | "dismissed" | "fixed"
--   dependency.package.ecosystem                    — "npm" | "pip" | "maven" | etc.
--   dependency.package.name                         — package name
--   dependency.manifest_path                        — e.g. "package.json"
--   dependency.scope                                — "runtime" | "development"
--   security_advisory.ghsa_id                       — "GHSA-xxxx-xxxx-xxxx"
--   security_advisory.cve_id                        — "CVE-YYYY-NNNNN" or null
--   security_advisory.summary                       — short title
--   security_advisory.description                   — longer description
--   security_advisory.severity                      — "low"|"medium"|"high"|"critical"
--   security_advisory.cvss.score                    — float 0-10 or null
--   security_advisory.cvss.vector_string            — CVSS vector string or null
--   security_advisory.identifiers[]                 — [{type:"CVE",value:"CVE-..."},...]
--   security_vulnerability.vulnerable_version_range — e.g. "< 4.17.21"
--   security_vulnerability.first_patched_version.identifier — e.g. "4.17.21"
--   auto_dismissed_at                               — ISO 8601 or null
--   created_at                                      — ISO 8601
--   updated_at                                      — ISO 8601
--   html_url                                        — alert URL
--   repo_name                                       — injected by connector: "owner/repo"

DELETE FROM schema_mapping WHERE scanner = 'dependabot';

INSERT INTO schema_mapping (scanner, source_field, canonical_field, transform, notes) VALUES

  -- Identity
  ('dependabot', 'security_advisory.ghsa_id',
    'source_vuln_id',
    '{"type":"direct"}',
    'GHSA ID is the primary Dependabot vuln identifier'),

  -- CVE
  ('dependabot', 'security_advisory.cve_id',
    'cve_id',
    '{"type":"direct"}',
    'GitHub provides cve_id directly on the advisory; null if no CVE assigned'),

  ('dependabot', 'security_advisory.identifiers',
    'all_cves',
    '{"type":"array_filter_by_key","key":"type","value":"CVE","extract":"value"}',
    'Filter identifiers array for type=CVE, collect the value strings'),

  -- Title / description
  ('dependabot', 'security_advisory.summary',
    'title',
    '{"type":"direct","fallback_field":"security_advisory.ghsa_id"}',
    'Fall back to GHSA ID if summary is empty'),

  ('dependabot', 'security_advisory.description',
    'description',
    '{"type":"direct"}',
    NULL),

  -- Severity — GitHub uses lowercase strings; canonical needs Title Case
  ('dependabot', 'security_advisory.severity',
    'severity',
    '{"type":"lookup","map":{"low":"Low","medium":"Medium","high":"High","critical":"Critical"},"default":"Medium"}',
    'Dependabot severity string → canonical 5-level'),

  -- CVSS
  ('dependabot', 'security_advisory.cvss.score',
    'cvss_score',
    '{"type":"direct"}',
    'Pre-computed CVSS score; null if GitHub has not computed one'),

  ('dependabot', 'security_advisory.cvss.vector_string',
    'cvss_version',
    '{"type":"cvss_vector_to_version"}',
    'Infer 2.0 / 3.0 / 3.1 from the vector string prefix (AV: vs CVSS:3.0 vs CVSS:3.1)'),

  -- Solution — upgrade instruction derived from first_patched_version
  ('dependabot', 'security_vulnerability.first_patched_version.identifier',
    'solution',
    '{"type":"template","text":"Upgrade {dependency.package.name} to {value}"}',
    'Concrete upgrade instruction; null if no patched version known'),

  -- Package
  ('dependabot', 'dependency.package.name',
    'package.name',
    '{"type":"jsonb_set"}',
    NULL),

  ('dependabot', 'dependency.package.ecosystem',
    'package.ecosystem',
    '{"type":"jsonb_set"}',
    'npm | pip | maven | rubygems | nuget | cargo | go | etc.'),

  ('dependabot', 'security_vulnerability.first_patched_version.identifier',
    'package.fixed_version',
    '{"type":"jsonb_set"}',
    'The version that fixes the vulnerability'),

  -- Asset identity — repo-scoped
  ('dependabot', 'repo_name',
    'asset_identity.repo',
    '{"type":"jsonb_set"}',
    'Injected by connector as "owner/repo"'),

  ('dependabot', 'dependency.manifest_path',
    'asset_identity.manifest',
    '{"type":"jsonb_set"}',
    'e.g. package.json, requirements.txt'),

  ('dependabot', 'dependency.scope',
    'asset_identity.dependency_scope',
    '{"type":"jsonb_set"}',
    '"runtime" or "development"'),

  -- Timestamps
  ('dependabot', 'created_at',
    'first_detected',
    '{"type":"iso_to_timestamptz"}',
    'When the alert was first opened')

ON CONFLICT (scanner, source_field, canonical_field) DO UPDATE SET
  transform  = EXCLUDED.transform,
  notes      = EXCLUDED.notes,
  updated_at = now();

-- (no trailing UPDATE needed — the INSERT ... ON CONFLICT above is the
--  single source of truth for the dependabot registry row)

-- =============================================================================
-- 4. Reset watermark — force a full re-fetch on next scan
-- =============================================================================
-- Clears last_fetched_at so the connector does not skip alerts that were
-- already fetched before this migration was applied. Without this, the
-- watermark filter would suppress all existing alerts.

UPDATE connection_registry
SET last_fetched_at = NULL
WHERE tool = 'dependabot';
