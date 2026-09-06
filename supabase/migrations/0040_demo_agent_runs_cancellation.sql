-- 0040_demo_agent_runs_cancellation.sql
--
-- Bring `demo.agent_runs` in line with `public.agent_runs` (migration 0030)
-- so the demo pipeline supports the same operator Stop-Run flow.
--
-- Without this migration:
--   • POST /agents/demo/runs/{id}/cancel  → 500 (cancellation_requested
--     column doesn't exist)
--   • Any UPDATE that tries to set status='cancelled' on demo.agent_runs
--     → 23514 check-constraint violation.
--
-- With this migration:
--   • Cancel endpoint writes cancellation_requested=true + status='cancelled'.
--   • `is_cancellation_requested_demo(run_id)` reads the flag and returns
--     true; master aborts on next iteration; SA-4 watchdog aborts on next
--     phase boundary (≤30s).

-- Add the flag if not already present. Idempotent.
ALTER TABLE demo.agent_runs
  ADD COLUMN IF NOT EXISTS cancellation_requested boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN demo.agent_runs.cancellation_requested IS
  'Operator has requested cancellation. Master + SA-4 watchdog poll this and abort at the next checkpoint. Mirrors public.agent_runs.cancellation_requested.';

-- Expand the status CHECK to permit ''cancelled''. The constraint name in
-- the demo schema may or may not match public''s convention; drop by lookup
-- rather than by hard-coded name so this runs against any deployment shape.
DO $$
DECLARE
  _con text;
BEGIN
  FOR _con IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'demo'
      AND t.relname = 'agent_runs'
      AND c.contype = 'c'
      AND pg_get_constraintdef(c.oid) ILIKE '%status%'
  LOOP
    EXECUTE format('ALTER TABLE demo.agent_runs DROP CONSTRAINT %I', _con);
  END LOOP;
END $$;

ALTER TABLE demo.agent_runs
  ADD CONSTRAINT agent_runs_status_check
  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));
