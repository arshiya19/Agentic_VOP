-- =============================================================================
-- Agentic_VOP — Cancellation support for in-flight agent runs
-- =============================================================================
-- Adds a cancellation flag to agent_runs so a user can stop an active fetch
-- mid-flight. The Master + Sub-Agents poll this flag at checkpoints and
-- gracefully exit early when set.
--
-- The accompanying /agents/runs/{run_id}/cancel endpoint sets this flag,
-- marks the run as 'cancelled', and wipes the targeted scanner's data from
-- issues + raw_findings (so the user gets a clean state to retry).
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

ALTER TABLE agent_runs
  ADD COLUMN IF NOT EXISTS cancellation_requested boolean NOT NULL DEFAULT false;

-- Widen the status CHECK to include 'cancelled'
ALTER TABLE agent_runs DROP CONSTRAINT IF EXISTS agent_runs_status_check;
ALTER TABLE agent_runs ADD CONSTRAINT agent_runs_status_check
  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));

COMMENT ON COLUMN agent_runs.cancellation_requested IS
  'Set to true by POST /agents/runs/{run_id}/cancel. The Master + Sub-Agents '
  'poll this flag at checkpoints and exit early when true.';
