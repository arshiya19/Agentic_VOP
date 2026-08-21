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

from ..config import FixerConfig
from .code_edit_strategy import CodeEditStrategy


class DependencyStrategy(CodeEditStrategy):
    """Strategy for SCA findings — edits dependency manifests (requirements.txt, etc.).

    Inherits all behavior from CodeEditStrategy. Only overrides identity
    fields for clean tracing and DB persistence.
    """

    name = "Dependency (SCA)"
    strategy_key = "dependency"

    def __init__(self, *, config: FixerConfig, emit_fn) -> None:
        super().__init__(config=config, emit_fn=emit_fn)
