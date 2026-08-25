"""DependencyStrategy — concrete strategy for SCA (dependency vulnerability) findings.

Thin subclass of CodeEditStrategy. The fix shape is identical (edit a manifest
file, verify the vulnerable pin is gone, re-scan with the SCA scanner), but
we give it a distinct name and strategy_key so traces and fix_runs clearly
distinguish "bumped a requirements.txt pin" from "refactored Python source
to use parameterized queries".

Handles findings from:
  - trivy-fs (Python requirements.txt, package.json, pom.xml, go.mod, etc.)
  - snyk-appsec (same manifest targets)
  - dependabot (GitHub advisory-driven version bumps)
  - osv (Open Source Vulnerabilities)

Future enhancements (Phase-3) that would live HERE, not in CodeEditStrategy:
  - Lockfile regeneration (pip-compile, npm install --package-lock-only)
  - Transitive dependency resolution (--dry-run install + conflict detection)
  - Compatibility check (run test suite after bump)

For Phase-2, the fix is simply: edit the version pin in the manifest →
re-scan to confirm the CVE is gone. CodeEditStrategy's execute/validate/
rollback machinery handles that perfectly.
"""

from __future__ import annotations

import re

from ..config import FixerConfig
from ..models import FixContext, PreFlightResult
from .base import verify_tools
from .code_edit_strategy import CodeEditStrategy


# Runtime-mutating package-manager verbs. When SA-4 sees one of these in a
# dep-fix step, it skips it — a file-based SCA scanner (trivy-fs, snyk-appsec)
# validates from the manifest bytes, not the installed runtime, so the install
# adds nothing to the outcome and can permanently corrupt the shared sandbox
# when a bumped dep introduces a new ABI break (the classic cryptography ⇢
# pyOpenSSL cascade). Pattern matches word-boundary so `pip install` skips but
# `pip-tools` (a different binary) does not.
_RUNTIME_MUTATION_RE = re.compile(
    r"\b("
    r"pip3?\s+install|pip3?\s+uninstall|"
    r"python3?\s+-m\s+pip\s+(install|uninstall|upgrade)|"
    r"npm\s+install|npm\s+i\s|npm\s+uninstall|npm\s+update|"
    r"yarn\s+(add|remove|install|upgrade)|"
    r"pnpm\s+(add|remove|install|update)|"
    r"bundle\s+(install|update|add|remove)|"
    r"gem\s+install|gem\s+uninstall|"
    r"poetry\s+(install|add|remove|update)|"
    r"go\s+install|go\s+get|"
    r"cargo\s+(install|add|remove)|"
    r"mvn\s+install|"
    r"apt-get\s+(install|remove|purge|upgrade|dist-upgrade)|"
    r"apt\s+(install|remove|purge|upgrade)|"
    r"yum\s+(install|remove|update)|"
    r"dnf\s+(install|remove|update)"
    r")\b",
    re.IGNORECASE,
)

# Runtime import-based version checks (only meaningful if the install
# actually ran — which we skip above). Also catches the `python`-vs-`python3`
# binary-not-found error mode on Ubuntu 20.04 where only `python3` exists.
_RUNTIME_IMPORT_CHECK_RE = re.compile(
    r"\bpython3?\s+-c\s+['\"]?\s*import\s+",
    re.IGNORECASE,
)


# Manifest-extension → CLI tool the fix will invoke. Only tools that respond
# to `--version` belong here (verify_tools uses that probe). If the manifest
# doesn't match any pattern, we skip the extra check (empty list) — same
# behavior as before this helper existed.
_MANIFEST_TOOLS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    # Python: requirements.txt / requirements-*.in / pyproject.toml / Pipfile / poetry.lock
    (
        ("requirements", ".txt", ".in", "pyproject.toml", "pipfile", "poetry.lock"),
        ("python3", "pip"),
    ),
    # Node: package.json / package-lock.json / yarn.lock / pnpm-lock.yaml
    (("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"), ("npm",)),
    # Ruby
    (("gemfile", "gemfile.lock"), ("bundle",)),
    # Go
    (("go.mod", "go.sum"), ("go",)),
    # Java (Maven)
    (("pom.xml",), ("mvn",)),
    # Java (Gradle)
    (("build.gradle", "build.gradle.kts"), ("gradle",)),
    # Rust
    (("cargo.toml", "cargo.lock"), ("cargo",)),
)


class DependencyStrategy(CodeEditStrategy):
    """Strategy for SCA findings — edits dependency manifests (requirements.txt, etc.).

    Inherits execute/validate/rollback from CodeEditStrategy. Extends
    pre_flight_check with a manifest-inferred tool availability probe so
    a broken package-manager binary (pip/npm/etc.) surfaces at pre-flight
    with a clear error_message instead of every plan rolling back at the
    `install` step with a generic "exit status 1".
    """

    name = "Dependency (SCA)"
    strategy_key = "dependency"

    def __init__(self, *, config: FixerConfig, emit_fn) -> None:
        super().__init__(config=config, emit_fn=emit_fn)

    def pre_flight_check(self, ctx: FixContext) -> PreFlightResult:
        base = super().pre_flight_check(ctx)
        if not base.ready:
            return base

        tools = self._tools_for_manifest(ctx.file_path or "")
        if not tools:
            return base

        executor = self._executor_for(ctx)
        extra_checks, blocking = verify_tools(
            executor,
            list(tools),
            emit=lambda et, msg: self._emit(ctx, et, msg),
        )
        checks = list(base.checks) + extra_checks
        if blocking:
            return PreFlightResult(ready=False, checks=checks, blocking_reason=blocking)
        return PreFlightResult(ready=True, checks=checks)

    def _should_skip_shell_step(self, command: str, ctx: FixContext) -> str | None:  # noqa: ARG002
        """Skip runtime-mutating installs and runtime version checks.

        Trivy-fs / snyk-appsec / dependabot / osv all scan the manifest file.
        A corrected pin in requirements.txt satisfies the re-scan; actually
        running `pip install --upgrade` adds no scanner value and can permanently
        break the shared sandbox (observed 2026-08-24: cryptography install
        broke pyOpenSSL, cascading rollbacks across every subsequent dep run).

        The scanner re-scan step still runs (doesn't match either regex).
        """
        # Don't touch the re-scan step — it must always run
        if self._looks_like_rescan(command):
            return None
        if _RUNTIME_MUTATION_RE.search(command):
            return (
                "dep strategy is manifest-only — runtime package-manager "
                "install/upgrade would mutate the shared sandbox and is not "
                "needed to satisfy the file-based scanner"
            )
        if _RUNTIME_IMPORT_CHECK_RE.search(command):
            return (
                "dep strategy skips runtime import checks — validation is "
                "the scanner re-scan, not a `python -c import` (which would "
                "also fail on Ubuntu 20.04 where only `python3` exists)"
            )
        return None

    @staticmethod
    def _tools_for_manifest(file_path: str) -> tuple[str, ...]:
        lower = (file_path or "").lower()
        if not lower:
            return ()
        base_name = lower.rsplit("/", 1)[-1]
        for markers, tools in _MANIFEST_TOOLS:
            if any(m in base_name or lower.endswith(m) for m in markers):
                return tools
        return ()
