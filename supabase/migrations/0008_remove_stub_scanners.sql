-- =============================================================================
-- Agentic_VOP — remove DB-stub scanners (keep only the live Tenable connector)
-- =============================================================================
-- Removes connector_registry + prompt_db entries for trivy_results, qualys,
-- owasp, snyk. They'll come back when we wire real connectors for each.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

DELETE FROM prompt_db
WHERE agent IN (
  'sub-agent-1-trivy_results',
  'sub-agent-1-qualys',
  'sub-agent-1-owasp',
  'sub-agent-1-snyk'
);

DELETE FROM connection_registry
WHERE tool IN ('trivy_results', 'qualys', 'owasp', 'snyk');

-- Optional: also remove any schema_mapping rows that referenced the stub-only
-- scanners. (Tenable mapping rows stay since the live connector returns the
-- same row shape as the legacy table.)
DELETE FROM schema_mapping
WHERE scanner IN ('trivy_results', 'qualys', 'owasp', 'snyk');
