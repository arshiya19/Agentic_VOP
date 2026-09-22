"""HITL v2 Git-native review — Phase B (side experiment).

Companion to the sandbox review flow (see `review.py`). Where the sandbox
mode edits a file on our env2 EC2 and pauses for the reviewer, this module
edits a file in a cloned copy of the customer's GitHub repo and opens a
real Pull Request. The reviewer sees the diff on GitHub. Approve merges
the PR via the GitHub API; Reject closes it.

This module is DELIBERATELY ISOLATED from the sandbox flow:
  • The orchestrator only imports it when a package is flagged
    `hitl_git_review=True` (default False).
  • It uses `subprocess` + PyGithub — no SSM, no env2 involvement at all.
  • Failure is graceful — every function returns a typed result the caller
    can branch on; nothing raises into master.

Primitives, in the order they run per fix:

  1. `clone_repo()`         — shallow clone into a temp dir
  2. `create_branch()`      — checkout a fresh branch off base
  3. `apply_shell_commands()` — run SA-3's remediation_steps AS-IS in cwd
  4. `commit_all()`         — git add . && git commit
  5. `push_branch()`        — push to the fork
  6. `open_pr()`            — POST /repos/{owner}/{repo}/pulls
  7. cleanup temp dir

Later — for Approve/Reject endpoints:

  • `merge_pr(pr_number)`   — PUT /repos/{owner}/{repo}/pulls/{n}/merge
  • `close_pr(pr_number)`   — PATCH state=closed
  • `get_pr_state(pr)`      — GET /repos/{owner}/{repo}/pulls/{n}

Everything routes through the `GitReviewClient` so credentials live in
one place and never touch trace logs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any


# ─── Result types — the caller pattern-matches on these ────────────────────
@dataclass(frozen=True)
class GitOpResult:
    ok: bool
    message: str
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class PROpened:
    ok: bool
    pr_number: int | None
    pr_url: str | None
    branch_name: str | None
    message: str
    commits: int = 0


@dataclass(frozen=True)
class PRState:
    ok: bool
    number: int | None
    state: str | None  # "open" | "closed" | "merged" | "unknown"
    merged: bool
    mergeable: bool | None  # None when GitHub hasn't computed yet
    html_url: str | None
    head_sha: str | None
    message: str


# =============================================================================
# Client — one instance per operation, cheap to construct
# =============================================================================
class GitReviewClient:
    """Bundles PAT + repo config + a temp working directory for one fix.

    Instantiate per-fix (not a singleton) so working dirs stay isolated and
    a stuck operation on one package can't strand another.
    """

    def __init__(
        self,
        *,
        pat: str,
        repo: str,
        base_branch: str = "main",
        work_dir: str | None = None,
    ) -> None:
        """
        Args:
            pat: GitHub Personal Access Token with contents+pulls write scope.
            repo: 'owner/name' (e.g. 'revanth3132/vop-git-review-demo').
            base_branch: branch to open PRs against (default 'main').
            work_dir: optional temp dir; auto-created + cleaned when None.
        """
        if not pat or not repo:
            raise ValueError("git_review: PAT and repo are required")
        self.pat = pat
        self.repo = repo
        self.base_branch = base_branch
        self._owned_work_dir = work_dir is None
        self._work_dir = work_dir or tempfile.mkdtemp(prefix="vop-git-review-")
        self._local_path: str | None = None  # set after clone

    # ------------------------------------------------------------------ setup
    def __enter__(self) -> GitReviewClient:
        return self

    def __exit__(self, *_) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Remove the temp working dir. Safe to call multiple times."""
        if self._owned_work_dir and self._work_dir and os.path.isdir(self._work_dir):
            try:
                shutil.rmtree(self._work_dir, ignore_errors=True)
            except Exception:  # noqa: BLE001, S110
                pass

    # ---------------------------------------------------------------- helpers
    def _remote_url(self) -> str:
        """HTTPS URL with PAT embedded for git clone/push. Never logged."""
        # x-access-token is GitHub's convention for PAT-based basic auth over HTTPS.
        return f"https://x-access-token:{self.pat}@github.com/{self.repo}.git"

    def _redact(self, text: str) -> str:
        """Scrub the PAT from any subprocess output before it leaves the module."""
        if not text:
            return text
        return text.replace(self.pat, "***").replace(
            f"x-access-token:{self.pat}", "x-access-token:***"
        )

    def _run_git(
        self,
        args: list[str],
        *,
        cwd: str | None = None,
        timeout_s: int = 120,
    ) -> GitOpResult:
        """subprocess.run wrapper that never leaks the PAT into logs."""
        try:
            r = subprocess.run(
                ["git", *args],  # noqa: S607 — git resolved via PATH by design
                cwd=cwd or self._local_path or self._work_dir,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            return GitOpResult(
                ok=r.returncode == 0,
                message=f"git {args[0]} exit={r.returncode}",
                stdout=self._redact(r.stdout or "")[:2000],
                stderr=self._redact(r.stderr or "")[:2000],
            )
        except subprocess.TimeoutExpired:
            return GitOpResult(
                ok=False,
                message=f"git {args[0]} timed out after {timeout_s}s",
            )
        except FileNotFoundError:
            return GitOpResult(
                ok=False,
                message="git binary not found on PATH — install git or set PATH",
            )
        except Exception as e:  # noqa: BLE001
            return GitOpResult(
                ok=False,
                message=f"git {args[0]} crashed: {type(e).__name__}: {str(e)[:200]}",
            )

    # ---------------------------------------------------------------- steps
    def clone(self, *, depth: int = 5) -> GitOpResult:
        """Shallow clone to self._work_dir. Depth kept small — we only need
        the base branch head + a few commits back for merge-base sanity."""
        target = os.path.join(self._work_dir, "repo")
        r = self._run_git(
            [
                "clone",
                "--depth",
                str(depth),
                "--branch",
                self.base_branch,
                self._remote_url(),
                target,
            ],
            cwd=self._work_dir,
            timeout_s=180,
        )
        if r.ok:
            self._local_path = target
            # Set a stable local identity so commits have an author line.
            self._run_git(["config", "user.email", "vop-bot@agentic-vop.local"])
            self._run_git(["config", "user.name", "VOP Bot"])
        return r

    def create_branch(self, branch_name: str) -> GitOpResult:
        """Checkout a fresh branch off the base."""
        return self._run_git(["checkout", "-b", branch_name])

    def apply_shell_commands(
        self,
        commands: list[str],
        *,
        timeout_s: int = 120,
    ) -> list[dict[str, Any]]:
        """Run each SA-3 remediation-step shell command in the cloned dir.

        Same commands SA-4 would run on env2, just executed locally via
        subprocess instead of via SSM. Each command's stdout/stderr/exit
        is captured for the caller to persist as `fix_run.step_results`.
        """
        results: list[dict[str, Any]] = []
        for i, cmd in enumerate(commands, start=1):
            try:
                r = subprocess.run(  # noqa: S602 — SA-3 shell commands; runs against a cloned repo, not env2
                    cmd,
                    cwd=self._local_path,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    check=False,
                )
                results.append(
                    {
                        "step": i,
                        "command": cmd[:500],
                        "status": "success" if r.returncode == 0 else "failed",
                        "exit_code": r.returncode,
                        "stdout": self._redact(r.stdout or "")[:1000],
                        "stderr": self._redact(r.stderr or "")[:1000],
                    }
                )
            except subprocess.TimeoutExpired:
                results.append(
                    {
                        "step": i,
                        "command": cmd[:500],
                        "status": "timeout",
                        "exit_code": -1,
                        "stderr": f"timed out after {timeout_s}s",
                    }
                )
            except Exception as e:  # noqa: BLE001
                results.append(
                    {
                        "step": i,
                        "command": cmd[:500],
                        "status": "crashed",
                        "exit_code": -1,
                        "stderr": f"{type(e).__name__}: {str(e)[:200]}",
                    }
                )
        return results

    def has_changes(self) -> bool:
        """True if `git status` shows any staged/unstaged/untracked changes."""
        r = self._run_git(["status", "--porcelain"])
        return r.ok and bool((r.stdout or "").strip())

    def commit_all(self, message: str) -> GitOpResult:
        """git add -A + git commit. No-op safe — returns ok=False with a
        clear message if there's nothing to commit."""
        if not self.has_changes():
            return GitOpResult(ok=False, message="no changes to commit")
        add = self._run_git(["add", "-A"])
        if not add.ok:
            return add
        return self._run_git(["commit", "-m", message])

    def push_branch(self, branch_name: str) -> GitOpResult:
        """Push the current branch to origin with upstream tracking."""
        return self._run_git(
            ["push", "-u", "origin", branch_name],
            timeout_s=120,
        )

    # ------------------------------------------------------------------ PR API
    def open_pr(
        self,
        *,
        head_branch: str,
        title: str,
        body: str,
    ) -> PROpened:
        """POST a new PR via PyGithub. Returns PROpened for the caller to
        persist onto the package row."""
        try:
            from github import Github, GithubException  # noqa: PLC0415
        except ImportError as e:
            return PROpened(
                ok=False,
                pr_number=None,
                pr_url=None,
                branch_name=head_branch,
                message=f"PyGithub not installed: {e}",
            )

        try:
            gh = Github(self.pat)
            gh_repo = gh.get_repo(self.repo)
            pr = gh_repo.create_pull(
                title=title[:250],
                body=body[:60000],
                head=head_branch,
                base=self.base_branch,
                maintainer_can_modify=True,
            )
            return PROpened(
                ok=True,
                pr_number=pr.number,
                pr_url=pr.html_url,
                branch_name=head_branch,
                message="PR opened",
                commits=pr.commits,
            )
        except GithubException as e:
            return PROpened(
                ok=False,
                pr_number=None,
                pr_url=None,
                branch_name=head_branch,
                message=f"GitHub API error ({e.status}): {str(e.data)[:200]}",
            )
        except Exception as e:  # noqa: BLE001
            return PROpened(
                ok=False,
                pr_number=None,
                pr_url=None,
                branch_name=head_branch,
                message=f"open_pr crashed: {type(e).__name__}: {str(e)[:200]}",
            )


# =============================================================================
# Standalone functions — for Approve/Reject endpoints that don't need clone
# =============================================================================
def merge_pr(
    *,
    pat: str,
    repo: str,
    pr_number: int,
    commit_title: str | None = None,
    merge_method: str = "squash",
) -> tuple[bool, str]:
    """Merge an open PR via the GitHub API. Returns (ok, message).

    `merge_method` is 'squash' by default — keeps history clean on the
    base branch. Set to 'merge' or 'rebase' if the customer prefers.
    """
    try:
        from github import Github, GithubException  # noqa: PLC0415

        gh = Github(pat)
        gh_repo = gh.get_repo(repo)
        pr = gh_repo.get_pull(pr_number)
        if pr.merged:
            return True, f"PR #{pr_number} already merged"
        if pr.state != "open":
            return False, f"PR #{pr_number} is {pr.state!r}, cannot merge"
        result = pr.merge(
            commit_title=(commit_title or f"Merge PR #{pr_number} (VOP HITL Review)")[:250],
            merge_method=merge_method,
        )
        return bool(result.merged), (result.message or "merged")
    except GithubException as e:
        return False, f"GitHub API error ({e.status}): {str(e.data)[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, f"merge_pr crashed: {type(e).__name__}: {str(e)[:200]}"


def close_pr(
    *,
    pat: str,
    repo: str,
    pr_number: int,
    comment: str | None = None,
) -> tuple[bool, str]:
    """Close a PR without merging. Optionally posts a comment first
    explaining the rejection so reviewers see context in the PR history."""
    try:
        from github import Github, GithubException  # noqa: PLC0415

        gh = Github(pat)
        gh_repo = gh.get_repo(repo)
        pr = gh_repo.get_pull(pr_number)
        if pr.state == "closed":
            return True, f"PR #{pr_number} already closed"
        if comment:
            try:
                pr.create_issue_comment(comment[:8000])
            except Exception:  # noqa: BLE001, S110
                pass
        pr.edit(state="closed")
        return True, "closed"
    except GithubException as e:
        return False, f"GitHub API error ({e.status}): {str(e.data)[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, f"close_pr crashed: {type(e).__name__}: {str(e)[:200]}"


def get_pr_state(*, pat: str, repo: str, pr_number: int) -> PRState:
    """Fetch current PR state — used by the UI mirror + webhook reconciler."""
    try:
        from github import Github, GithubException  # noqa: PLC0415

        gh = Github(pat)
        gh_repo = gh.get_repo(repo)
        pr = gh_repo.get_pull(pr_number)
        # GitHub returns state='closed' whether merged or not — check .merged
        # separately for the accurate terminal state.
        canonical_state = "merged" if pr.merged else pr.state
        return PRState(
            ok=True,
            number=pr.number,
            state=canonical_state,
            merged=pr.merged,
            mergeable=pr.mergeable,
            html_url=pr.html_url,
            head_sha=pr.head.sha if pr.head else None,
            message="ok",
        )
    except GithubException as e:
        return PRState(
            ok=False,
            number=pr_number,
            state=None,
            merged=False,
            mergeable=None,
            html_url=None,
            head_sha=None,
            message=f"GitHub API error ({e.status}): {str(e.data)[:200]}",
        )
    except Exception as e:  # noqa: BLE001
        return PRState(
            ok=False,
            number=pr_number,
            state=None,
            merged=False,
            mergeable=None,
            html_url=None,
            head_sha=None,
            message=f"get_pr_state crashed: {type(e).__name__}: {str(e)[:200]}",
        )


def test_connection(*, pat: str, repo: str) -> tuple[bool, str]:
    """Cheap health check used at startup and by the trigger endpoint.
    Confirms the PAT has read access to the target repo before we try
    to open a PR (better to fail fast + loud than mid-flow)."""
    try:
        from github import Github, GithubException  # noqa: PLC0415

        gh = Github(pat)
        gh_repo = gh.get_repo(repo)
        return True, f"ok — {gh_repo.full_name} (default={gh_repo.default_branch})"
    except GithubException as e:
        return False, f"GitHub API error ({e.status}): {str(e.data)[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, f"test_connection crashed: {type(e).__name__}: {str(e)[:200]}"
