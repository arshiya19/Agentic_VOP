-- =============================================================================
-- Agentic_VOP — drop fingerprint dedup
-- =============================================================================
-- Decision (2026-04-29): no dedup at the issues layer. Each scan run produces
-- fresh rows. Multiple scanners reporting the same CVE+asset → multiple rows.
-- Re-running the same scan → more rows. This preserves a clean audit trail.
-- Aggregation / "unique findings" views happen at query time, not write time.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

-- Drop the unique constraint and the fingerprint column itself
ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_fingerprint_key;
ALTER TABLE issues DROP COLUMN IF EXISTS fingerprint;

-- Optional: clear out existing rows from earlier (deduped) runs so we start
-- with a clean append-only history. UNCOMMENT if you want a fresh start.
-- TRUNCATE TABLE issues RESTART IDENTITY CASCADE;
