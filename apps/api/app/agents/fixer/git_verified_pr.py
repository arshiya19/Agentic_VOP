"""Post-success PR hook — opens a "verified" PR AFTER the sandbox flow
succeeded and the trivy/checkov rescan proved the CVE is gone.

Contrast with the previous experiment (git_review_lifecycle.py, now removed):
that one *replaced* SA-4 with a git flow, skipping env2 entirely — the PR
carried the code change but no proof it worked. This hook does the opposite:
sandbox runs in full, empirically verifies the fix, and only then do we mirror
the same edit into the customer's repo as a PR. The PR body carries the
validation output as evidence.

Pitch: *"We ran your fix in our sandbox, verified with a rescan, here's the
one-line change to apply."*

Called from `orchestrator._run_lifecycle` just before it returns
`StrategyOutcome(status="success")`. Best-effort — if the PR open fails, the
sandbox fix stays in `fixed` state; only the PR side-effect is missed.
"""

from __future__ import annotations

import re
from typing import Any

from .git_review import GitReviewClient
from .models import ValidationResult


_ENV2_PATH_PREFIXES = (
    "/opt/vuln-labs/cspm-lab/",
    "/opt/vuln-labs/appsec-lab/",
    "/opt/vuln-labs/serverless-lab/",
    "/opt/vuln-labs/infra-lab/",
    "/opt/vuln-labs/java-image-lab/",
    "/opt/vuln-labs/python-image-lab/",
    "/opt/vuln-labs/",
)

_BACKUP_CMD_RE = re.compile(r"\bcp\s+\S+\s+\S+\.bak-\S+")

_SANDBOX_CMD_TOKENS = (
    "docker",
    "docker-compose",
    "systemctl",
    "service",
    "apt-get",
    "apt",
    "yum",
    "dnf",
    "trivy",
)

_SED_INPLACE_RE = re.compile(r"\bsed\s+-i\s+(?P<script>'[^']*'|\"[^\"]*\")\s+(?P<file>\S+)")

_SHELL_BLOCK_RE = re.compile(r"```(?:bash|sh|shell)?\n([\s\S]*?)```", re.MULTILINE)


def _is_sandbox_only_cmd(cmd: str) -> bool:
    stripped = cmd.strip()
    while stripped.startswith("cd "):
        parts = stripped.split("&&", 1)
        if len(parts) != 2:
            break
        stripped = parts[1].strip()
    first = stripped.split(None, 1)[0] if stripped else ""
    return first in _SANDBOX_CMD_TOKENS


def _portable_sed(cmd: str) -> str:
    m = _SED_INPLACE_RE.search(cmd)
    if not m:
        return cmd
    script, fpath = m.group("script"), m.group("file")
    replacement = f"sed -i.tmp {script} {fpath} && rm -f {fpath}.tmp"
    return cmd[: m.start()] + replacement + cmd[m.end() :]


def _rewrite_for_repo(commands: list[str]) -> list[str]:
    out: list[str] = []
    for cmd in commands:
        if _BACKUP_CMD_RE.search(cmd):
            continue
        if _is_sandbox_only_cmd(cmd):
            continue
        for prefix in _ENV2_PATH_PREFIXES:
            cmd = cmd.replace(prefix, "")
        cmd = _portable_sed(cmd)
        out.append(cmd)
    return out


def _extract_shell_commands(step_text: str) -> list[str]:
    """Pull runnable commands out of a SA-3 step blob. Same conventions as
    git_review_lifecycle.
    """
    commands: list[str] = []
    for block in _SHELL_BLOCK_RE.findall(step_text or ""):
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                commands.append(line)
    if commands:
        return commands
    # Fall back: inline `Command: X` or multi-line indented block
    lines = (step_text or "").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^\s*Command:\s*(.+)$", line)
        if m and m.group(1).strip():
            commands.append(m.group(1).strip())
            i += 1
            continue
        if re.match(r"^\s*Command:\s*$", line):
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    break
                if re.match(r"^\s*(Why|Expected|Test):", nxt):
                    break
                if nxt.startswith((" ", "\t")):
                    stripped = nxt.strip()
                    if stripped and not stripped.startswith("#"):
                        commands.append(stripped)
                    i += 1
                else:
                    break
            continue
        i += 1
    return commands


def _branch_name(pkg_row: dict) -> str:
    pkg_id = pkg_row.get("id", 0)
    check_id = ""
    for pw in pkg_row.get("pathways") or []:
        title = pw.get("objective") or ""
        m = re.search(r"(CKV[_A-Z0-9]+|CVE-\d{4}-\d{4,7})", title)
        if m:
            check_id = m.group(1)
            break
    slug = re.sub(r"[^A-Za-z0-9]+", "-", check_id.lower()).strip("-") or "verified"
    return f"vop/verified-{slug}-{pkg_id}"


def _pr_title(pkg_row: dict) -> str:
    finding = (pkg_row.get("finding") or "security fix")[:70]
    return f"[Verified] {finding}"


def _pr_body(
    pkg_row: dict,
    package_id: int,
    fix_run_id: int,
    agent_run_id: str,
    validation_results: list[ValidationResult],
) -> str:
    finding = pkg_row.get("finding") or "(no finding text)"
    root_cause = pkg_row.get("root_cause") or "(no root cause text)"
    family = pkg_row.get("family") or "unknown"

    rescan_lines: list[str] = []
    other_lines: list[str] = []
    for vr in validation_results or []:
        line = (
            f"- **{'✅' if vr.passed else '❌'} {vr.test_name}** "
            f"({vr.method}) — expected `{vr.expected[:60]}`, "
            f"got `{vr.actual[:60]}`"
        )
        if vr.is_rescan:
            rescan_lines.append(line)
        else:
            other_lines.append(line)

    rescan_section = "\n".join(rescan_lines) if rescan_lines else "_no scanner rescan recorded_"
    other_section = "\n".join(other_lines) if other_lines else "_none_"

    return f"""### Verified remediation from VOP

**This fix was applied and verified in an isolated sandbox before this PR was opened.**

**Finding**
{finding}

**Root cause**
{root_cause}

**Family:** `{family}` · **Package:** `#{package_id}` · **Fix run:** `#{fix_run_id}` · **Agent run:** `{agent_run_id[:8]}`

---

### Sandbox validation (proof)

**Scanner rescan** (authoritative — CVE / rule verified absent):
{rescan_section}

**Ancillary checks:**
{other_section}

---

### What this PR does

The single-file edit below is the exact change that the sandbox proved fixes
the finding. Merging this PR brings the same change into `main` for your
deploy pipeline to pick up.

- ✅ **Merge** — the fix lands on `main`; your CI/CD deploys it
- ❌ **Close** — no change lands; the finding stays open

You can also **Approve** / **Reject** directly in the VOP Remediation
page — it calls GitHub's merge/close API on your behalf.
"""


def open_verified_pr(
    *,
    sb: Any,
    package_id: int,
    pkg_row: dict,
    fix_run_id: int,
    agent_run_id: str,
    validation_results: list[ValidationResult],
    emit_fn,
    pat: str,
    repo: str,
    base_branch: str,
) -> None:
    """Open a verified PR reflecting the sandbox-proven fix.

    Best-effort: any failure inside this function is emitted as a warning
    but does NOT flip the successful sandbox run. Caller has already
    written status='success' — this is purely additive.
    """
    pathway_index = int(pkg_row.get("recommended_pathway_index") or 0)
    pathways = pkg_row.get("pathways") or []
    if pathway_index >= len(pathways):
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Verified-PR: no valid pathway on package #{package_id}, skipping PR",
        )
        return
    pathway = pathways[pathway_index]

    raw_steps = pathway.get("remediation_steps") or []
    commands: list[str] = []
    for st in raw_steps:
        if isinstance(st, dict):
            for cmd in _extract_shell_commands(st.get("step") or ""):
                commands.append(cmd)
    commands = _rewrite_for_repo(commands)
    if not commands:
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Verified-PR: no repo-runnable commands after rewrite for pkg #{package_id}, skipping PR",
        )
        return

    branch_name = _branch_name(pkg_row)
    try:
        with GitReviewClient(pat=pat, repo=repo, base_branch=base_branch) as client:
            r = client.clone()
            if not r.ok:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Verified-PR: clone failed — {r.message}",
                )
                return
            r = client.create_branch(branch_name)
            if not r.ok:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Verified-PR: branch failed — {r.message}",
                )
                return
            client.apply_shell_commands(commands, timeout_s=120)
            if not client.has_changes():
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    "⚠ Verified-PR: no repo changes produced (edit already present?) — skipping PR",
                )
                return
            finding = (pkg_row.get("finding") or "security fix")[:120]
            r = client.commit_all(f"fix (verified): {finding}")
            if not r.ok:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Verified-PR: commit failed — {r.message}",
                )
                return
            r = client.push_branch(branch_name)
            if not r.ok:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Verified-PR: push failed — {r.message}",
                )
                return
            pr = client.open_pr(
                head_branch=branch_name,
                title=_pr_title(pkg_row),
                body=_pr_body(pkg_row, package_id, fix_run_id, agent_run_id, validation_results),
            )
            if not pr.ok or not pr.pr_url:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Verified-PR: open_pr failed — {pr.message}",
                )
                return
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"🔀 Verified PR #{pr.pr_number} opened → {pr.pr_url}",
            )
            try:
                sb.table("remediation_packages").update(
                    {
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
                    "MESSAGE",
                    f"⚠ Verified-PR: PR opened but package update failed — {type(e).__name__}",
                )
    except Exception as e:  # noqa: BLE001
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Verified-PR: crashed — {type(e).__name__}: {str(e)[:200]}",
        )
