-- 0039_remediation_package_fix_outcomes.sql
--
-- Extend the status CHECK constraint on remediation_packages to include
-- terminal fix-outcome states. These are set by the HITL approve flow
-- after Sub-Agent 4 completes (see apps/api/app/main.py approve endpoint
-- background task) so the Remediation page reflects the fix result instead
-- of staying stuck at "ready_for_execution" forever.
--
-- New values:
--   fixed        — SA-4 succeeded, scanner rescan confirmed CVE gone
--   rolled_back  — SA-4 attempted, scanner rescan still found CVE, backup restored
--   fix_failed   — SA-4 crashed or otherwise didn't reach a terminal state
--
-- The three original workflow states are preserved unchanged:
--   draft, awaiting_approval, approved, rejected, ready_for_execution
--
-- Applied to BOTH public.remediation_packages and demo.remediation_packages
-- since the demo schema mirrors public.

DO $$
DECLARE
  _constraint_name text;
BEGIN
  FOR _constraint_name IN
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
         WHERE c.conname=_constraint_name LIMIT 1),
      _constraint_name
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
    'fix_failed'
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
    'fix_failed'
  ));
