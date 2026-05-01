-- =============================================================================
-- Agentic_VOP — incremental fetch watermark
-- =============================================================================
-- Adds a per-tool "watermark" timestamp to connection_registry. Sub-Agent 1
-- uses it to fetch only NEW findings (created after the watermark) and then
-- advances the watermark after a successful run.
--
-- Result: no duplicate ingestion. Same pattern works for DB stub today and
-- real scanner APIs tomorrow.
--
-- To force a full re-fetch (demo / debugging):
--   UPDATE connection_registry SET last_fetched_at = NULL WHERE tool = 'tenable';
-- =============================================================================

ALTER TABLE connection_registry
  ADD COLUMN IF NOT EXISTS last_fetched_at timestamptz;

COMMENT ON COLUMN connection_registry.last_fetched_at IS
  'Watermark — Sub-Agent 1 fetches rows created after this timestamp. Advances after each successful run. NULL = never fetched (full pull).';
