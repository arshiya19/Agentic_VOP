-- 0043_fix_runs_git_review_strategy.sql
--
-- HITL v2 git-native review (side experiment).
--
-- Extends fix_runs.strategy CHECK constraint to allow a new value:
--
--   git_review  — SA-4 applied the fix inside a cloned Git repo (branch +
--                 commit + PR), rather than on env2 via SSM. There is no
--                 SSM RunCommand, no .bak file, and no strategy class; the
--                 branch itself is the rollback and the PR is the review
--                 surface.
--
-- Applied to BOTH public.fix_runs and demo.fix_runs. Existing rows and
-- non-git flows are untouched — this is strictly additive.

ALTER TABLE public.fix_runs DROP CONSTRAINT IF EXISTS fix_runs_strategy_check;
ALTER TABLE public.fix_runs DROP CONSTRAINT IF EXISTS dev_fix_runs_strategy_check;
ALTER TABLE demo.fix_runs   DROP CONSTRAINT IF EXISTS demo_fix_runs_strategy_check;
ALTER TABLE demo.fix_runs   DROP CONSTRAINT IF EXISTS fix_runs_strategy_check;

ALTER TABLE public.fix_runs
  ADD CONSTRAINT fix_runs_strategy_check
  CHECK (strategy IN ('iac','cli','dependency','code_edit','image','os','git_review'));

ALTER TABLE demo.fix_runs
  ADD CONSTRAINT demo_fix_runs_strategy_check
  CHECK (strategy IN ('iac','cli','dependency','code_edit','image','os','git_review'));
