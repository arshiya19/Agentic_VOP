-- =============================================================================
-- Agentic_VOP — SBOM-driven asset attribution (assets.dependencies)
-- =============================================================================
-- Adds a Software Bill of Materials column to `assets`. Every asset declares
-- the packages it contains, by ecosystem:
--
--   {"npm": ["lodash","axios"], "PyPI": ["pyyaml"], "Maven": ["groupId:artifactId"]}
--
-- When a package-level scanner (OSV, Trivy, Snyk, Dependabot) reports a CVE
-- against `lodash@4.17.15`, the matcher does a single lookup:
--
--   "which asset's dependencies.npm contains 'lodash'?" → customer-portal
--
-- Zero per-scanner aliases. Zero per-finding hand-curated mapping. The CMDB
-- is the single source of truth; package scanners auto-attribute.
--
-- This permanently retires the alias-per-scanner pattern. Aliases stay only
-- for true synonyms (e.g. asset also known as a different host name).
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

ALTER TABLE assets
  ADD COLUMN IF NOT EXISTS dependencies jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN assets.dependencies IS
  'Software Bill of Materials by ecosystem. Shape: '
  '{"npm":["lodash","axios"], "PyPI":["pyyaml"], "Maven":["groupId:artifactId"]}. '
  'Used by _resolve_asset() to auto-attribute findings from package-level '
  'scanners (OSV, Trivy, Snyk, Dependabot) without per-scanner alias tables.';

-- GIN index for the eventual reverse-lookup query
-- (SELECT name FROM assets WHERE dependencies->'npm' ? 'lodash')
CREATE INDEX IF NOT EXISTS idx_assets_dependencies
  ON assets USING gin (dependencies);


-- =============================================================================
-- Seed: derive SBOM from the existing monitored_packages mapping
-- =============================================================================
-- monitored_packages already says which package belongs to which "service"
-- (via the label column). We translate that to canonical asset names:
--
--   label "web-frontend"  → customer-portal (public JS app)
--   label "data-pipeline" → mongo-prod-01   (hosts the data pipeline's data)
--   label "java-service"  → payments-api    (the only service-type asset)
--
-- The npm package list also captures the dep tree we've seen from Trivy
-- (axios, lodash, express, qs, tar, path-to-regexp) — so a single dependencies
-- entry covers OSV + Trivy + any future scanner without per-scanner work.
-- =============================================================================

UPDATE assets
SET dependencies = jsonb_build_object(
      'npm', to_jsonb(ARRAY[
        'lodash','minimist','axios','express','qs','tar','path-to-regexp'
      ]::text[])
    ),
    updated_at = now()
WHERE name = 'customer-portal';

UPDATE assets
SET dependencies = jsonb_build_object(
      'npm',  to_jsonb(ARRAY['mongoose']::text[]),
      'PyPI', to_jsonb(ARRAY['pyyaml','pillow','requests']::text[])
    ),
    updated_at = now()
WHERE name = 'mongo-prod-01';

UPDATE assets
SET dependencies = jsonb_build_object(
      'Maven', to_jsonb(ARRAY[
        'org.apache.logging.log4j:log4j-core',
        'com.fasterxml.jackson.core:jackson-databind'
      ]::text[])
    ),
    updated_at = now()
WHERE name = 'payments-api';


-- =============================================================================
-- Sanity check after applying:
-- =============================================================================
--   -- Confirm the SBOM seed:
--   SELECT name, jsonb_pretty(dependencies) AS sbom
--   FROM assets
--   WHERE dependencies != '{}'::jsonb
--   ORDER BY name;
--
--   -- Reverse-lookup test (which asset owns lodash?):
--   SELECT name FROM assets
--   WHERE dependencies->'npm' ? 'lodash';
--   -- Expected: customer-portal
--
--   -- After the next rescore, OSV attribution should jump from 0 to N:
--   SELECT
--     count(*) FILTER (WHERE (components_summary->'factors'->>'env_f')::numeric != 1.00) AS attributed,
--     count(*) AS total
--   FROM issues WHERE source = 'osv';
