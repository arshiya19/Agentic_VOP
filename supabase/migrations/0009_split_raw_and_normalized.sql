-- =============================================================================
-- Agentic_VOP — split raw scanner output and normalized issues into two tables
-- =============================================================================
-- Sub-Agent 1 is now a 2-step pipeline:
--   1. Fetch from scanner   → write to raw_findings (verbatim, by tool)
--   2. Normalize each row   → write to issues (canonical schema, FK to raw)
--
-- Why: clean separation of "what the scanner said" vs "what we made of it".
-- Replay: if normalization logic changes, re-run from raw_findings without
-- re-hitting the scanner. Audit: side-by-side diff of raw and canonical.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================


-- 1. Wipe leftover canonical issues from earlier runs to start clean
TRUNCATE TABLE issues RESTART IDENTITY CASCADE;


-- 2. Drop the inline source_raw jsonb from issues — raw lives in raw_findings now
ALTER TABLE issues DROP COLUMN IF EXISTS source_raw;


-- 3. Create raw_findings — generic verbatim store
CREATE TABLE IF NOT EXISTS raw_findings (
  id            bigserial PRIMARY KEY,
  source        text NOT NULL,                                    -- 'tenable', 'trivy', etc.
  agent_run_id  uuid REFERENCES agent_runs(run_id) ON DELETE SET NULL,
  raw           jsonb NOT NULL,                                   -- the original row, byte-exact
  fetched_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_raw_findings_source        ON raw_findings(source);
CREATE INDEX IF NOT EXISTS idx_raw_findings_agent_run_id  ON raw_findings(agent_run_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_fetched_at    ON raw_findings(fetched_at DESC);

COMMENT ON TABLE raw_findings IS
  'Raw scanner rows persisted verbatim. issues.raw_finding_id references this.';


-- 4. Add raw_finding_id FK to issues
ALTER TABLE issues
  ADD COLUMN IF NOT EXISTS raw_finding_id bigint REFERENCES raw_findings(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_issues_raw_finding_id ON issues(raw_finding_id);


-- 5. RLS + Realtime on raw_findings (mirrors the issues table posture)
ALTER TABLE raw_findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "auth read" ON raw_findings FOR SELECT TO authenticated USING (true);

ALTER PUBLICATION supabase_realtime ADD TABLE raw_findings;


-- 6. Reset the Tenable watermark so the next run pulls fresh
UPDATE connection_registry SET last_fetched_at = NULL WHERE tool = 'tenable';
