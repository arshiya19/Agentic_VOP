-- =============================================================================
-- 0013 — Drop closed CHECK constraint on issues.source
--
-- Now that the Integrations page lets users register arbitrary scanner tools
-- (via the Phase 2 "user_endpoint" connector), the historic whitelist
-- (tenable, trivy, qualys, owasp, snyk, osv) is too restrictive — any new
-- tool slug a user registers would be rejected at insert time.
--
-- Sub-Agent 1 now forces `issue.source = <registered tool slug>` in code, so
-- correctness is guaranteed at the application layer; the DB just needs to
-- accept whatever slug shows up.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_source_check;
