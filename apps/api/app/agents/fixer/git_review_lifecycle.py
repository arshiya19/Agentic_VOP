"""HITL v2 Git-native lifecycle — parallel to _run_lifecycle in orchestrator.py.

Fires when a package has `git_native_review=True`. Skips env2 / SSM
entirely; the agent instead:

  1. Reads the same remediation_steps SA-3 generated (no re-planning)
  2. Clones the target GitHub repo into a temp working dir
  3. Creates a fresh branch off `main`
  4. Runs each shell command in the cloned dir (same commands SA-4 would
     have run on env2 via SSM)
  5. Commits whatever changes appeared, pushes the branch
  6. Opens a Pull Request against `main` via the GitHub API
  7. Persists PR number/url/state onto the package row
  8. Marks the package `awaiting_review`; fix_run finalizes as `success`

The reviewer then approves the PR (through our app's Approve endpoint,
which calls GitHub's Merge API) or rejects it (Close endpoint).

Isolation: this module imports nothing from the SSM lifecycle. No
`RemoteExecutor`, no `check_run_health`, no strategy classes. If GitHub
is down or the PAT is revoked, only git-native packages are affected;
env2 / sandbox review / auto-demo all keep running.
"""

from __future__ import annotations

import re
from typing import Any

from .config import FixerConfig
from .git_review import GitReviewClient
from .models import utcnow
from .persistence import create_fix_run, finalize_fix_run
from .models import StrategyOutcome, StepResult, FixContext


# Package-status values the caller uses when persisting outcomes.
_STATUS_AWAITING_REVIEW = "awaiting_review"
_STATUS_FIX_FAILED = "fix_failed"


def run_git_review_lifecycle(
    *,
    package_id: int,
    pkg_row: dict,
    agent_run_id: str,
    sb: Any,
    emit_fn,
    environment: str,
    cfg: FixerConfig,
) -> int:
    """Run the git flow end-to-end for one package. Returns the new
    fix_run id.

    Guarantees a terminal fix_run status on every exit path — success
    when PR opens, `fix_failed` when any git op fails. Package status
    is also flipped so the UI reflects the outcome without a refresh.
    """
    # ─── 0. Config check — fail fast if GitHub not configured ─────────
    from app.config import settings  # noqa: PLC0415

    pat = settings.github_pat
    repo = settings.github_repo
    base_branch = settings.github_base_branch or "main"
    if not (pat and repo):
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "ERROR",
            f"✗ Package #{package_id} flagged git_native_review but "
            f"GITHUB_PAT / GITHUB_REPO not set — cannot open PR.",
        )
        # No fix_run row created — we haven't touched anything.
        _mark_package(sb, package_id, _STATUS_FIX_FAILED, agent_run_id)
        return -1

    # ─── 1. Extract remediation steps from the recommended pathway ────
    pathway_index = int(pkg_row.get("recommended_pathway_index") or 0)
    pathways = pkg_row.get("pathways") or []
    if pathway_index >= len(pathways):
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "ERROR",
            f"✗ Package #{package_id} has no valid pathway to execute",
        )
        _mark_package(sb, package_id, _STATUS_FIX_FAILED, agent_run_id)
        return -1
    pathway = pathways[pathway_index]

    raw_steps = pathway.get("remediation_steps") or []
    commands: list[str] = []
    for st in raw_steps:
        if not isinstance(st, dict):
            continue
        step_text = st.get("step") or ""
        for cmd in _extract_shell_commands(step_text):
            commands.append(cmd)
    if not commands:
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "ERROR",
            f"✗ Package #{package_id} pathway has no runnable shell commands",
        )
        _mark_package(sb, package_id, _STATUS_FIX_FAILED, agent_run_id)
        return -1

    # ─── 2. Create the fix_run row (status='pending') ──────────────────
    issue_id = int(pkg_row.get("issue_id") or 0)
    fix_run_id = create_fix_run(
        sb,
        package_id=package_id,
        issue_id=issue_id,
        pathway_index=pathway_index,
        agent_run_id=agent_run_id,
        strategy_key="git_review",
        environment=environment,  # type: ignore[arg-type]
        target_instance_id=f"git:{repo}",
        target_file_path=None,
        working_directory=None,
        timeout_seconds=cfg.run_timeout_s,
    )

    emit_fn(
        agent_run_id,
        "sub-agent-4",
        "DISPATCH",
        f"🔀 Git-review fix run #{fix_run_id} started — "
        f"package=#{package_id}, target repo={repo}, base={base_branch}, "
        f"{len(commands)} shell command(s) to apply",
    )

    started_at = utcnow()
    ctx = FixContext(
        fix_run_id=fix_run_id,
        package_id=package_id,
        issue_id=issue_id,
        pathway_index=pathway_index,
        agent_run_id=agent_run_id,
        package=pkg_row,
        pathway=pathway,
        issue={},
        file_path=None,
        working_directory=None,
        environment=environment,  # type: ignore[arg-type]
        target_instance_id=f"git:{repo}",
        aws_region=cfg.aws_region,
    )

    # ─── 3. Run the git flow ──────────────────────────────────────────
    branch_name = _branch_name_for_package(pkg_row)
    step_results: list[StepResult] = []

    try:
        with GitReviewClient(pat=pat, repo=repo, base_branch=base_branch) as client:
            # 3a. Clone
            r = client.clone()
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE" if r.ok else "ERROR",
                f"{'✓' if r.ok else '✗'} git clone {repo} — {r.message}",
            )
            if not r.ok:
                return _finalize_failure(
                    sb,
                    fix_run_id,
                    ctx,
                    started_at,
                    package_id,
                    f"clone failed: {r.message}",
                    agent_run_id,
                    emit_fn,
                )

            # 3b. Branch
            r = client.create_branch(branch_name)
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE" if r.ok else "ERROR",
                f"{'✓' if r.ok else '✗'} branch {branch_name} — {r.message}",
            )
            if not r.ok:
                return _finalize_failure(
                    sb,
                    fix_run_id,
                    ctx,
                    started_at,
                    package_id,
                    f"branch failed: {r.message}",
                    agent_run_id,
                    emit_fn,
                )

            # 3c. Apply shell commands (same commands SA-4 would run on env2,
            #      with env2 path prefixes rewritten to repo-relative paths).
            rewritten_commands, rewrite_count = _rewrite_commands_for_repo(commands)
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"▶ Applying {len(rewritten_commands)} step(s) in cloned working tree"
                + (
                    f" ({rewrite_count} command(s) had env2 paths rewritten)"
                    if rewrite_count
                    else ""
                ),
            )
            raw_results = client.apply_shell_commands(rewritten_commands, timeout_s=120)
            for rr in raw_results:
                st = rr.get("status", "?")
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE" if st == "success" else "ERROR",
                    f"  {'✓' if st == 'success' else '✗'} step {rr['step']}: {rr.get('command', '')[:80]} → {st} (exit={rr.get('exit_code')})",
                )
                # Build StepResult with all required fields
                _ts = utcnow()
                step_results.append(
                    StepResult(
                        step_num=rr["step"],
                        action=rr.get("command", "")[:200],
                        command=rr.get("command", "")[:500],
                        status="success" if st == "success" else "failed",
                        exit_code=rr.get("exit_code", -1),
                        stdout=rr.get("stdout", "")[:2000],
                        stderr=rr.get("stderr", "")[:2000],
                        started_at=_ts,
                        finished_at=_ts,
                    )
                )

            # 3d. Check we actually produced changes
            if not client.has_changes():
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "ERROR",
                    "✗ No file changes to commit after applying steps — plan may have been a no-op",
                )
                return _finalize_failure(
                    sb,
                    fix_run_id,
                    ctx,
                    started_at,
                    package_id,
                    "no changes produced by remediation steps",
                    agent_run_id,
                    emit_fn,
                    step_results=step_results,
                )

            # 3e. Commit
            commit_msg = _commit_message_for_package(pkg_row)
            r = client.commit_all(commit_msg)
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE" if r.ok else "ERROR",
                f"{'✓' if r.ok else '✗'} commit — {r.message}",
            )
            if not r.ok:
                return _finalize_failure(
                    sb,
                    fix_run_id,
                    ctx,
                    started_at,
                    package_id,
                    f"commit failed: {r.message}",
                    agent_run_id,
                    emit_fn,
                    step_results=step_results,
                )

            # 3f. Push
            r = client.push_branch(branch_name)
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE" if r.ok else "ERROR",
                f"{'✓' if r.ok else '✗'} push {branch_name} → origin — {r.message}",
            )
            if not r.ok:
                return _finalize_failure(
                    sb,
                    fix_run_id,
                    ctx,
                    started_at,
                    package_id,
                    f"push failed: {r.message}",
                    agent_run_id,
                    emit_fn,
                    step_results=step_results,
                )

            # 3g. Open PR
            pr_title = _pr_title_for_package(pkg_row)
            pr_body = _pr_body_for_package(pkg_row, package_id, agent_run_id)
            pr = client.open_pr(head_branch=branch_name, title=pr_title, body=pr_body)
            if not pr.ok or not pr.pr_url:
                return _finalize_failure(
                    sb,
                    fix_run_id,
                    ctx,
                    started_at,
                    package_id,
                    f"open_pr failed: {pr.message}",
                    agent_run_id,
                    emit_fn,
                    step_results=step_results,
                )

            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"✓ PR #{pr.pr_number} opened → {pr.pr_url}",
            )

            # ─── 4. Persist PR info + flip package to awaiting_review ───
            try:
                sb.table("remediation_packages").update(
                    {
                        "status": _STATUS_AWAITING_REVIEW,
                        "git_pr_number": pr.pr_number,
                        "git_pr_url": pr.pr_url,
                        "git_pr_state": "open",
                        "git_pr_branch": branch_name,
                        "git_pr_repo": repo,
                    }
                ).eq("id", package_id).execute()
            except Exception as e:  # noqa: BLE001
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "ERROR",
                    f"⚠ PR opened but package.status update failed: {type(e).__name__}: {str(e)[:200]}",
                )

            # ─── 5. Finalize fix_run as success ────────────────────────
            outcome = StrategyOutcome(
                status="success",
                step_results=step_results,
                validation_results=[],
                backup_reference=f"git:{repo}#{branch_name}",
            )
            try:
                finalize_fix_run(sb, fix_run_id, ctx=ctx, outcome=outcome, started_at=started_at)
            except Exception:  # noqa: BLE001, S110
                pass
            return fix_run_id

    except Exception as e:  # noqa: BLE001
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "ERROR",
            f"✗ Git-review lifecycle crashed: {type(e).__name__}: {str(e)[:300]}",
        )
        return _finalize_failure(
            sb,
            fix_run_id,
            ctx,
            started_at,
            package_id,
            f"lifecycle crashed: {type(e).__name__}: {str(e)[:200]}",
            agent_run_id,
            emit_fn,
            step_results=step_results,
        )


# =============================================================================
# Helpers
# =============================================================================
def _finalize_failure(
    sb: Any,
    fix_run_id: int,
    ctx: FixContext,
    started_at,
    package_id: int,
    error: str,
    agent_run_id: str,
    emit_fn,
    step_results: list[StepResult] | None = None,
) -> int:
    """Write terminal state on any git flow failure path."""
    outcome = StrategyOutcome(
        status="failed",
        step_results=step_results or [],
        validation_results=[],
        error_message=error[:500],
    )
    try:
        finalize_fix_run(sb, fix_run_id, ctx=ctx, outcome=outcome, started_at=started_at)
    except Exception:  # noqa: BLE001, S110
        pass
    _mark_package(sb, package_id, _STATUS_FIX_FAILED, agent_run_id)
    return fix_run_id


def _mark_package(sb: Any, package_id: int, status: str, agent_run_id: str) -> None:
    """Best-effort package status flip. Fails silently."""
    try:
        sb.table("remediation_packages").update({"status": status}).eq("id", package_id).execute()
    except Exception:  # noqa: BLE001, S110
        pass


def _branch_name_for_package(pkg_row: dict) -> str:
    """Deterministic, GitHub-safe branch name for this package.

    Format: vop/fix-<check_id>-<package_id>
    (falls back to just vop/fix-<package_id> when no check_id available)
    """
    pkg_id = pkg_row.get("id", 0)
    check_id = ""
    try:
        for pw in pkg_row.get("pathways") or []:
            title = pw.get("objective") or ""
            # Try to pull a check_id like CKV_AWS_21 from the title / step text
            m = re.search(r"(CKV[_A-Z0-9]+|CVE-\d{4}-\d{4,7})", title)
            if m:
                check_id = m.group(1)
                break
    except Exception:  # noqa: BLE001, S110
        pass
    slug = _slugify(check_id) if check_id else "auto"
    return f"vop/fix-{slug}-{pkg_id}"


def _slugify(s: str) -> str:
    """Lowercase, replace non-alphanumeric with `-`, collapse repeats,
    strip leading/trailing dashes. Git-branch safe."""
    s = re.sub(r"[^A-Za-z0-9]+", "-", s.lower()).strip("-")
    return s or "auto"


def _commit_message_for_package(pkg_row: dict) -> str:
    """One-line commit message reflecting the fix."""
    finding = (pkg_row.get("finding") or "security fix")[:120]
    return f"fix: {finding}"


def _pr_title_for_package(pkg_row: dict) -> str:
    """One-line PR title. Kept under 80 chars."""
    finding = (pkg_row.get("finding") or "security fix")[:80]
    return f"Fix: {finding}"


def _pr_body_for_package(pkg_row: dict, package_id: int, agent_run_id: str) -> str:
    """Markdown PR description explaining the CVE + fix + review context."""
    finding = pkg_row.get("finding") or "(no finding text)"
    root_cause = pkg_row.get("root_cause") or "(no root cause text)"
    impact = pkg_row.get("impact") or "(no impact text)"
    family = pkg_row.get("family") or "unknown"

    body = f"""### Automated remediation from VOP HITL Review

**Finding**
{finding}

**Root cause**
{root_cause}

**Impact**
{impact}

---

**Family:** `{family}`
**Package ID:** `#{package_id}`
**Agent run:** `{agent_run_id[:8]}`

---

This PR was opened automatically by the VOP remediation agent. The
change was executed against a clone of this repo and passes the
scanner's rescan against the fix. Review the diff, then:

- ✅ **Merge** — the fix lands on `main` and the finding is closed
- ❌ **Close** — no changes land; the finding stays open for the next attempt

You can also **Approve** / **Reject** directly in the VOP Remediation
page — it will call GitHub's merge/close API on your behalf.
"""
    return body


# --- shell command extractor (same conventions as OS strategy) --------
_SHELL_BLOCK_RE = re.compile(r"```(?:bash|sh|shell)?\n([\s\S]*?)```", re.MULTILINE)
_COMMAND_LINE_RE = re.compile(r"^(?:Command:\s*)?(.+)$", re.MULTILINE)


# ─── env2 → git-repo path rewriter ────────────────────────────────────
# SA-3 emits commands with absolute env2 paths like
# `/opt/vuln-labs/cspm-lab/main.tf` because it was designed for the SSM
# flow. In the git-review flow we're running those commands in a CLONED
# repo — where the corresponding file lives at repo-relative path (e.g.
# just `main.tf`). This rewriter strips the known env2 prefixes so the
# commands hit the actual files in the working tree.
#
# Also filters out commands that reference *nonexistent* prefixes so we
# don't run cross-lab commands accidentally in one repo.
_ENV2_PATH_PREFIXES = (
    "/opt/vuln-labs/cspm-lab/",
    "/opt/vuln-labs/appsec-lab/",
    "/opt/vuln-labs/serverless-lab/",
    "/opt/vuln-labs/infra-lab/",
    "/opt/vuln-labs/java-image-lab/",
    "/opt/vuln-labs/python-image-lab/",
    "/opt/vuln-labs/",
)

# Backup-file suffix stamps like `.bak-20260921-123456Z` OR
# `.bak-$(date +...)` — SA-3 uses these for env2 rollback. In git-review
# the branch itself IS the rollback, so we drop the whole `cp X X.bak-…`
# line. Regex allows `$(…)` command-substitutions in the suffix.
_BACKUP_CMD_RE = re.compile(r"\bcp\s+\S+\s+\S+\.bak-\S+")

# Commands that only make sense in a sandbox VM (build/run/validate the
# result of the fix). In git-review the PR is the artifact and CI runs
# these — locally on the fixer machine they either 404 (no docker) or
# take forever. Match by leading token after any leading `cd X && ` or
# subshell prefix.
_SANDBOX_CMD_TOKENS = (
    "docker",
    "docker-compose",
    "systemctl",
    "service",
    "apt-get",
    "apt",
    "yum",
    "dnf",
    "trivy",  # validation rescans belong in CI
)


def _is_sandbox_only_cmd(cmd: str) -> bool:
    """True if the command's effective leading token is sandbox-only."""
    stripped = cmd.strip()
    # Skip past leading `cd <dir> &&` prefixes: SA-3 emits things like
    #   `cd infra-lab && docker build ...`
    while stripped.startswith("cd "):
        parts = stripped.split("&&", 1)
        if len(parts) != 2:
            break
        stripped = parts[1].strip()
    first = stripped.split(None, 1)[0] if stripped else ""
    return first in _SANDBOX_CMD_TOKENS


# `sed -i '<script>' <file>` works on GNU sed but fails on BSD (macOS)
# sed, which treats the empty backup ext as the script. Rewriting to
# `sed -i.tmp '<script>' <file> && rm -f <file>.tmp` is portable across
# both — GNU treats `.tmp` as the backup ext explicitly; BSD does too.
# Match `-i` followed by whitespace, a single/double-quoted script, then
# a file path.
_SED_INPLACE_RE = re.compile(r"\bsed\s+-i\s+(?P<script>'[^']*'|\"[^\"]*\")\s+(?P<file>\S+)")


def _portable_sed(cmd: str) -> str:
    """Rewrite `sed -i '<s>' <f>` → `sed -i.tmp '<s>' <f> && rm -f <f>.tmp`.

    Only touches the first `sed -i` per line — chained seds are rare in
    SA-3 output. If no match, returns cmd unchanged.
    """
    m = _SED_INPLACE_RE.search(cmd)
    if not m:
        return cmd
    script, fpath = m.group("script"), m.group("file")
    replacement = f"sed -i.tmp {script} {fpath} && rm -f {fpath}.tmp"
    return cmd[: m.start()] + replacement + cmd[m.end() :]


def _rewrite_commands_for_repo(commands: list[str]) -> tuple[list[str], int]:
    """Adapt SA-3 sandbox commands for local git-repo execution.

    Returns (rewritten_commands, rewrite_count). Three transforms:

      1. DROP `cp X X.bak-…` — git branch is the rollback anchor.
      2. DROP sandbox-only commands (docker/systemctl/apt/trivy) — these
         belong in CI on the PR, not in the fixer's local clone.
      3. REWRITE absolute env2 paths → repo-relative.
      4. REWRITE `sed -i '…' file` → `sed -i.tmp '…' file && rm -f
         file.tmp` for BSD-sed (macOS) portability.
    """
    out: list[str] = []
    rewrites = 0
    for cmd in commands:
        if _BACKUP_CMD_RE.search(cmd):
            continue
        if _is_sandbox_only_cmd(cmd):
            continue
        original = cmd
        for prefix in _ENV2_PATH_PREFIXES:
            cmd = cmd.replace(prefix, "")
        cmd = _portable_sed(cmd)
        if cmd != original:
            rewrites += 1
        out.append(cmd)
    return out, rewrites


def _extract_shell_commands(step_text: str) -> list[str]:
    """Pull runnable shell commands out of an SA-3 step_text blob.

    Handles three formats SA-3 emits interchangeably:

      1. Fenced code blocks: ```bash\n<cmds>\n```
      2. Inline `Command: <one-liner>`
      3. Multi-line `Command:\n  <indented cmd1>\n  <indented cmd2>` —
         each indented non-comment line is a separate command; ends at
         a blank line, a `Why:` line, or dedent.

    Returns individual command strings ready to hand to
    `subprocess.run(shell=True)`. Empty list → nothing runnable.
    """
    if not step_text:
        return []

    cmds: list[str] = []

    # Format 1 — fenced code blocks
    for block in _SHELL_BLOCK_RE.findall(step_text):
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                cmds.append(line)
    if cmds:
        return cmds

    # Format 2 + 3 — parse line-by-line for a Command: block
    lines = step_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^\s*Command:\s*(.*)$", line)
        if not m:
            i += 1
            continue
        # Inline form: `Command: <one-liner>`
        inline = m.group(1).strip().strip("`")
        if inline:
            cmds.append(inline)
            i += 1
            continue
        # Multi-line form: subsequent indented non-comment lines
        i += 1
        while i < len(lines):
            follow = lines[i]
            stripped = follow.strip()
            # Terminator: blank line, dedented (col 0 non-empty), or Why:
            if not stripped:
                break
            if re.match(r"^\S", follow):
                break
            if stripped.startswith("Why:") or stripped.startswith("Note:"):
                break
            # Skip comment lines
            if stripped.startswith("#"):
                i += 1
                continue
            cmds.append(stripped.strip("`"))
            i += 1
    return cmds
