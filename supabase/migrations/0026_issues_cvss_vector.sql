-- =============================================================================
-- Agentic_VOP — Capture raw CVSS vector + accept CVSS V4
-- =============================================================================
-- Some scanners (notably OSV.dev) ship only the CVSS vector string
--   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
-- and expect consumers to compute the numeric score from it. LLMs can't do
-- the CVSS subscore math reliably, so the previous flow dropped the score
-- entirely for those rows (~111 of 153 OSV findings empty in our data).
--
-- This migration:
--   1. Adds an issues.cvss_vector column to capture the raw vector verbatim
--      for audit + so a deterministic post-LLM helper in Sub-Agent 1 can
--      compute cvss_score + cvss_version from it.
--   2. Widens the cvss_version CHECK to accept '4.0' (OSV is starting to
--      ship CVSS V4 advisories; the model + DB used to reject them).
--
-- The actual vector-parsing logic ships in sub_agent_1.py using the `cvss`
-- Python package. After this migration + the code change, every future
-- finding from any scanner that emits a vector gets a numeric score with
-- zero hand-curation.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

ALTER TABLE issues
  ADD COLUMN IF NOT EXISTS cvss_vector text;

COMMENT ON COLUMN issues.cvss_vector IS
  'Raw CVSS vector string as emitted by the scanner, e.g. '
  '"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H". Sub-Agent 1 parses this '
  'deterministically (via the `cvss` Python lib) to fill cvss_score + cvss_version '
  'when the scanner does not pre-compute them. Preserved for audit so the '
  'derivation can be re-run if the scoring policy changes.';

-- Widen the version CHECK to accept V4
ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_cvss_version_check;
ALTER TABLE issues ADD CONSTRAINT issues_cvss_version_check
  CHECK (cvss_version IS NULL OR cvss_version IN ('2.0','3.0','3.1','4.0'));


-- =============================================================================
-- Sanity check after applying:
-- =============================================================================
--   -- Confirm the column exists and the CHECK constraint allows V4:
--   SELECT column_name, data_type FROM information_schema.columns
--   WHERE table_name='issues' AND column_name IN ('cvss_vector','cvss_version','cvss_score')
--   ORDER BY column_name;
--
--   -- After the backfill runs, OSV score coverage should jump:
--   SELECT source,
--          count(*) AS total,
--          count(cvss_score) AS with_score,
--          count(cvss_vector) AS with_vector
--   FROM issues
--   GROUP BY source ORDER BY source;
