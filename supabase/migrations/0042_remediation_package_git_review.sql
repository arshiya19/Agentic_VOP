-- 0042_remediation_package_git_review.sql
--
-- HITL v2 Git-native review (Phase B, side experiment).
--
-- ADDITIVE ONLY — no changes to existing columns, no CHECK constraint edits,
-- no touching sandbox review columns. Existing pipelines (auto-demo, HITL v1,
-- HITL v2 sandbox review) are completely unaffected. Rows that don't opt into
-- the git-review flow leave every new column NULL.
--
-- Adds on remediation_packages:
--   git_pr_number    — the GitHub PR number the agent opened for this fix
--   git_pr_url       — the html_url of that PR (for the "View on GitHub" link)
--   git_pr_state     — cached PR state: 'open' | 'closed' | 'merged'
--                      Updated by /review-git-approve, /review-git-reject,
--                      and (later) a webhook receiver.
--   git_pr_branch    — the head branch name the agent pushed (for cleanup)
--   git_pr_repo      — 'owner/name' the PR lives in (may differ per customer
--                      once we have multi-tenant; today read from GITHUB_REPO)
--
-- Applied to BOTH public.remediation_packages and demo.remediation_packages
-- so the same schema shape applies across real and demo pipelines.

ALTER TABLE public.remediation_packages
  ADD COLUMN IF NOT EXISTS git_native_review boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS git_pr_number  integer,
  ADD COLUMN IF NOT EXISTS git_pr_url     text,
  ADD COLUMN IF NOT EXISTS git_pr_state   text,
  ADD COLUMN IF NOT EXISTS git_pr_branch  text,
  ADD COLUMN IF NOT EXISTS git_pr_repo    text;

ALTER TABLE demo.remediation_packages
  ADD COLUMN IF NOT EXISTS git_native_review boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS git_pr_number  integer,
  ADD COLUMN IF NOT EXISTS git_pr_url     text,
  ADD COLUMN IF NOT EXISTS git_pr_state   text,
  ADD COLUMN IF NOT EXISTS git_pr_branch  text,
  ADD COLUMN IF NOT EXISTS git_pr_repo    text;

COMMENT ON COLUMN public.remediation_packages.git_pr_number IS
  'HITL v2 Git-native: GitHub PR number the agent opened. NULL for sandbox and non-review packages.';
COMMENT ON COLUMN public.remediation_packages.git_pr_url IS
  'HITL v2 Git-native: html_url of the PR. Rendered as a "View on GitHub" link in the Remediation card.';
COMMENT ON COLUMN public.remediation_packages.git_pr_state IS
  'HITL v2 Git-native: cached PR state — open | closed | merged. Updated by review endpoints; sourced from GitHub API.';
COMMENT ON COLUMN public.remediation_packages.git_pr_branch IS
  'HITL v2 Git-native: head branch name the agent pushed (e.g. vop/fix-CKV_AWS_21-...). Kept for cleanup after merge/close.';
COMMENT ON COLUMN public.remediation_packages.git_pr_repo IS
  'HITL v2 Git-native: owner/name of the repo the PR lives in. Read from GITHUB_REPO env var today; per-customer once multi-tenant lands.';

COMMENT ON COLUMN demo.remediation_packages.git_pr_number IS
  'HITL v2 Git-native: GitHub PR number the agent opened. NULL for sandbox and non-review packages.';
COMMENT ON COLUMN demo.remediation_packages.git_pr_url IS
  'HITL v2 Git-native: html_url of the PR. Rendered as a "View on GitHub" link in the Remediation card.';
COMMENT ON COLUMN demo.remediation_packages.git_pr_state IS
  'HITL v2 Git-native: cached PR state — open | closed | merged. Updated by review endpoints; sourced from GitHub API.';
COMMENT ON COLUMN demo.remediation_packages.git_pr_branch IS
  'HITL v2 Git-native: head branch name the agent pushed (e.g. vop/fix-CKV_AWS_21-...). Kept for cleanup after merge/close.';
COMMENT ON COLUMN demo.remediation_packages.git_pr_repo IS
  'HITL v2 Git-native: owner/name of the repo the PR lives in. Read from GITHUB_REPO env var today; per-customer once multi-tenant lands.';
