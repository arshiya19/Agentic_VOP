-- =============================================================================
-- Agentic_VOP — Package-name aliases on CMDB assets
-- =============================================================================
-- Lets _resolve_asset() attribute package-level scanner findings (Trivy, OSV,
-- Snyk, Dependabot) to the correct application by matching the scanner's
-- emitted PkgName / package_name against assets.aliases.
--
-- Without this migration: Trivy findings have asset_identity like
--   {"PkgName": "mongoose"} or {"package_name": "axios"} — the matcher's
--   "project" / "repo" / "hostname" / "ipv4" lookup keys all miss, so the
--   issue stays unattributed and the formula falls back to 1.0 multipliers.
--
-- With this migration + the matching code change in sub_agent_2._resolve_asset
-- (extended to also check PkgName / package_name), every future package-level
-- finding for the listed packages auto-attributes to the right asset.
--
-- This is the CMDB-as-source-of-truth approach: non-engineers can extend the
-- alias list as the app's dependency set grows, no code or prompt edits.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

-- mongoose is the MongoDB ORM — clearly belongs to the production Mongo cluster
UPDATE assets
SET aliases = ARRAY['mongoose'],
    updated_at = now()
WHERE name = 'mongo-prod-01';

-- customer-portal is the JS/Node customer-facing app — owns its npm dep tree
UPDATE assets
SET aliases = ARRAY[
      'axios',
      'lodash',
      'express',
      'qs',
      'tar',
      'path-to-regexp'
    ],
    updated_at = now()
WHERE name = 'customer-portal';


-- =============================================================================
-- Sanity check after applying:
-- =============================================================================
--   -- Confirm aliases populated:
--   SELECT name, aliases FROM assets
--   WHERE aliases IS NOT NULL AND array_length(aliases, 1) > 0
--   ORDER BY name;
--
--   -- After running POST /admin/issues/rescore, confirm Trivy attribution
--   -- now flows from aliases (components_summary.factors.env_f != 1.00):
--   SELECT
--     source,
--     count(*) FILTER (WHERE (components_summary->'factors'->>'env_f')::numeric != 1.00) AS attributed,
--     count(*) AS total
--   FROM issues
--   WHERE source IN ('trivy-cloud','osv')
--   GROUP BY source;
