-- =============================================================================
-- Agentic_VOP — swap the `tenable` connector from DB stub to LIVE Nessus API
-- =============================================================================
-- The other 4 scanners (trivy_results, qualys, owasp, snyk) keep using the
-- DB stub for now. Only Tenable goes live.
--
-- Requires:
--   TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in apps/api/.env
--   A running Nessus instance reachable from the API server (default
--   https://localhost:8834).
--
-- Watermark is reset to NULL so the first run pulls everything (subject to
-- scan_limit in metadata).
--
-- To revert to the DB stub, set metadata.connector_type back to "supabase_stub"
-- and endpoint back to the old project's REST URL.
-- =============================================================================

UPDATE connection_registry
SET
  protocol     = 'REST',
  endpoint     = 'https://localhost:8834',
  auth_type    = 'api_keys',
  auth_ref     = 'env://TENABLE_ACCESS_KEY+TENABLE_SECRET_KEY',
  metadata     = jsonb_build_object(
                   'connector_type', 'tenable_api',
                   'note', 'Real local Nessus instance via /scans/* + /plugins/*',
                   'scan_limit', 5
                 ),
  last_fetched_at = NULL,
  updated_at   = now()
WHERE tool = 'tenable';
