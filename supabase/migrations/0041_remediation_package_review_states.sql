-- 0041_remediation_package_review_states.sql
--
-- HITL v2 post-fix review — extends remediation_packages.status with two
-- new terminal states used by the review flow (see design doc: Post-Fix
-- Review Modes, Approach A · Sandbox).
--
--   awaiting_review  — SA-4 applied the fix, rescan passed, backup preserved;
--                      waiting for a human to click Approve or Reject on the
--                      diff shown in the Remediation page.
--
--   review_rejected  — human clicked Reject on the diff; SSM restored the
--                      backup; file is back to its pre-fix state.
--
-- Approve does NOT get a new state — approved reviews finalize as `fixed`,
-- which is already in the constraint (migration 0039).
--
-- Applied to BOTH public.remediation_packages and demo.remediation_packages.

DO $$
DECLARE
  _con text;
BEGIN
  FOR _con IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE t.relname = 'remediation_packages'
      AND c.contype = 'c'
      AND n.nspname IN ('public','demo')
      AND pg_get_constraintdef(c.oid) LIKE '%status%'
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.remediation_packages DROP CONSTRAINT %I',
      (SELECT n.nspname FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
         JOIN pg_namespace n ON n.oid=t.relnamespace
         WHERE c.conname=_con LIMIT 1),
      _con
    );
  END LOOP;
END $$;

ALTER TABLE public.remediation_packages
  ADD CONSTRAINT remediation_packages_status_check
  CHECK (status IN (
    'draft',
    'awaiting_approval',
    'approved',
    'rejected',
    'ready_for_execution',
    'fixed',
    'rolled_back',
    'fix_failed',
    'awaiting_review',
    'review_rejected'
  ));

ALTER TABLE demo.remediation_packages
  ADD CONSTRAINT remediation_packages_status_check
  CHECK (status IN (
    'draft',
    'awaiting_approval',
    'approved',
    'rejected',
    'ready_for_execution',
    'fixed',
    'rolled_back',
    'fix_failed',
    'awaiting_review',
    'review_rejected'
  ));

-- review_required flag on the package — set by planner when the pipeline
-- was triggered with HITL v2 review enabled. Backend checks this at end
-- of SA-4 validate phase to decide "pause for review" vs "finalize now."
--
-- Column is nullable + default false so existing rows stay unaffected.

ALTER TABLE public.remediation_packages
  ADD COLUMN IF NOT EXISTS review_required boolean NOT NULL DEFAULT false;

ALTER TABLE demo.remediation_packages
  ADD COLUMN IF NOT EXISTS review_required boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.remediation_packages.review_required IS
  'HITL v2: when true, SA-4 pauses after a successful validate + captures the diff, and the package awaits human approve/reject on the Remediation page before finalize.';
COMMENT ON COLUMN demo.remediation_packages.review_required IS
  'HITL v2: when true, SA-4 pauses after a successful validate + captures the diff, and the package awaits human approve/reject on the Remediation page before finalize.';

-- Diff storage on fix_runs — an array of {file_path, before, after,
-- unified_diff, bytes_changed} objects. JSONB so we don't pay a normalization
-- cost for what's essentially a bag of blobs per fix_run.

ALTER TABLE public.fix_runs
  ADD COLUMN IF NOT EXISTS review_diff jsonb;

ALTER TABLE demo.fix_runs
  ADD COLUMN IF NOT EXISTS review_diff jsonb;

COMMENT ON COLUMN public.fix_runs.review_diff IS
  'HITL v2: unified diff of every file this fix_run modified. Rendered by the Remediation page''s diff viewer. Shape: [{file_path, before, after, unified_diff, bytes_changed}].';
COMMENT ON COLUMN demo.fix_runs.review_diff IS
  'HITL v2: unified diff of every file this fix_run modified. Rendered by the Remediation page''s diff viewer. Shape: [{file_path, before, after, unified_diff, bytes_changed}].';
