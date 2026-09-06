"""Static validators for SA-3 output.

Catches deterministic LLM drift patterns BEFORE the plan is persisted +
dispatched to SA-4. Each broken plan we let through costs env2 60-180s of
wall-clock during rollback, so the ROI on cheap pre-flight checks is
enormous.

Validators return `ValidationIssue`s tagged `error` (block persistence) or
`warning` (log-only). Callers can choose to fail-hard or fail-soft based
on the highest severity returned.

Patterns caught (all observed in production drift):

  1. **no_op_sed** — `sed -i 's/openssl/openssl/'` — LHS == RHS. LLM
     emits an identity substitution as a placeholder when it doesn't know
     what to replace with. Fix runs report "success" but nothing changed.

  2. **wrong_tool_for_family** — `terraform state show vuln-image:latest`
     on an `image` family package. LLM reached for the wrong tool. Fixes
     always error; rollback fires immediately.

  3. **masked_failure** — test/validation commands ending in `|| true`
     or `2>/dev/null; exit 0`. LLM defensive habit that hides real errors
     the fixer's rescan gate depends on to trigger rollback.

  4. **rescan_cve_mismatch** — a validation command that greps for a CVE
     ID different from the finding's `source_vuln_id`. LLM substituted a
     "similar-looking" CVE. The finding never gets rescanned; wrong CVE
     may or may not pass; either way the pass/fail signal is meaningless.

Additional validators can plug in via `VALIDATORS` — same signature.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Guard against schema drift — pull the actual model class if importable,
# otherwise fall back to duck-typed dict access. Validators only need to
# see .pathways / .steps / .command / .code strings, so both shapes work.
try:
    from ..remediation.schema import RemediationPackage  # noqa: F401
except Exception:  # noqa: BLE001
    RemediationPackage = Any  # type: ignore[assignment,misc]


# =============================================================================
# Data types
# =============================================================================
@dataclass(frozen=True)
class ValidationIssue:
    check: str  # short slug: "no_op_sed", "wrong_tool_for_family", etc.
    severity: str  # "error" | "warning"
    message: str
    pathway_index: int
    step_index: int | None = None  # None when finding lives at pathway level


# =============================================================================
# Regexes — module-level compile so we don't pay per-package
# =============================================================================
# `sed -i 's/OLD/NEW/'` (also `-e`, no flag, escaped slashes, alt delimiters).
# Captures OLD and NEW so we can compare. Delimiter can be /, |, #, or , —
# matches whatever character follows the `s`.
_SED_SUB = re.compile(
    r"sed\s+(?:-i(?:\s+\S+)?|-e|-r|-E|--in-place=\S*)?\s*(?:['\"])?"
    r"s(?P<d>[/|#,])"
    r"(?P<lhs>(?:\\.|(?!(?P=d)).)*)"
    r"(?P=d)"
    r"(?P<rhs>(?:\\.|(?!(?P=d)).)*)"
    r"(?P=d)"
    r"[a-zA-Z0-9]*"  # flags: g, i, m, etc.
    r"(?:['\"])?",
)

# `... || true`, `... ; true`, `... || :`, `... 2>/dev/null; exit 0` — LLM
# patterns that swallow failure. We only flag when a command has NO business
# masking (test/validation), not general step commands.
_MASKED_FAILURE = re.compile(r"(\|\|\s*(?:true|:)\b|;\s*true\b|;\s*exit\s*0\b)")

# CVE identifier — anywhere in a command string.
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")

# terraform CLI invocation — matches `terraform <subcommand>` at word start
# regardless of prefix (cd; terraform / terraform ; etc.).
_TERRAFORM_CMD = re.compile(r"(?:^|[;&|\s])terraform\s+[a-z]", re.IGNORECASE)


# Steps that legitimately use `|| true`/`; exit 0`:
#   - backup steps (`cp foo foo.bak-... || true` — recovery on missing file)
#   - cleanup steps (`rm ... 2>/dev/null || true`)
# We detect these by keyword and skip the masked-failure check for them.
_MASK_ALLOWED_KEYWORDS = ("backup", "cleanup", "cleaning", "removing backup", "rm ")


# Families where terraform is the RIGHT tool. Anything not in this set
# should not use terraform commands.
_TERRAFORM_ALLOWED_FAMILIES = frozenset(
    {
        "public_exposure",  # IaC-managed AWS resources (S3, SG, IAM, KMS, ...)
        "network_exposure",
        "excessive_permissions",
        "unencrypted_storage",
        "misconfiguration",
    }
)


# =============================================================================
# Public API — run everything and return the flat list
# =============================================================================
def validate_package(pkg: Any, *, primary_issue: dict, family: str) -> list[ValidationIssue]:
    """Run all validators, return flat list of issues found.

    Empty list == plan is clean.
    """
    issues: list[ValidationIssue] = []
    for pi, pathway in enumerate(_iter_pathways(pkg)):
        for validator in _VALIDATORS:
            try:
                issues.extend(validator(pathway, pi, primary_issue, family))
            except Exception as e:  # noqa: BLE001
                # A validator crashing is a bug — don't let it hide real issues
                # or block a plan. Log via a synthetic warning.
                issues.append(
                    ValidationIssue(
                        check=f"validator_crashed:{validator.__name__}",
                        severity="warning",
                        message=f"{type(e).__name__}: {str(e)[:200]}",
                        pathway_index=pi,
                    )
                )
    return issues


def has_errors(issues: list[ValidationIssue]) -> bool:
    return any(i.severity == "error" for i in issues)


def summary(issues: list[ValidationIssue]) -> str:
    """One-line summary suitable for a trace event."""
    if not issues:
        return "no validator issues"
    by_sev: dict[str, int] = {}
    for i in issues:
        by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
    parts = [f"{n} {sev}" for sev, n in sorted(by_sev.items(), reverse=True)]
    return f"{sum(by_sev.values())} issue(s): {', '.join(parts)}"


# =============================================================================
# Individual validators
# =============================================================================
def _validate_no_op_sed(
    pathway: Any, pi: int, _primary: dict, _family: str
) -> list[ValidationIssue]:
    out: list[ValidationIssue] = []
    for si, step in enumerate(_iter_steps(pathway)):
        cmd = _step_command(step)
        if not cmd or "sed" not in cmd:
            continue
        for m in _SED_SUB.finditer(cmd):
            lhs = m.group("lhs")
            rhs = m.group("rhs")
            if lhs and lhs == rhs:
                out.append(
                    ValidationIssue(
                        check="no_op_sed",
                        severity="error",
                        message=(
                            f"step {si + 1} sed substitution is a no-op: "
                            f"s/{lhs[:40]}/{rhs[:40]}/ — LHS equals RHS, "
                            f"file will not be modified"
                        ),
                        pathway_index=pi,
                        step_index=si,
                    )
                )
    return out


def _validate_wrong_tool_for_family(
    pathway: Any, pi: int, _primary: dict, family: str
) -> list[ValidationIssue]:
    if family in _TERRAFORM_ALLOWED_FAMILIES:
        return []
    out: list[ValidationIssue] = []
    for si, step in enumerate(_iter_steps(pathway)):
        cmd = _step_command(step)
        if not cmd:
            continue
        if _TERRAFORM_CMD.search(cmd):
            out.append(
                ValidationIssue(
                    check="wrong_tool_for_family",
                    severity="error",
                    message=(
                        f"step {si + 1} uses `terraform` on a "
                        f"family={family!r} package — terraform is only "
                        f"valid for IaC families. Command starts: "
                        f"{cmd.strip()[:120]!r}"
                    ),
                    pathway_index=pi,
                    step_index=si,
                )
            )
    return out


def _validate_masked_failure(
    pathway: Any, pi: int, _primary: dict, _family: str
) -> list[ValidationIssue]:
    out: list[ValidationIssue] = []
    for si, step in enumerate(_iter_steps(pathway)):
        cmd = _step_command(step)
        if not cmd:
            continue
        step_kind = _step_kind(step)
        # Skip backup/cleanup — masked failure is fine there.
        if step_kind and any(kw in step_kind.lower() for kw in _MASK_ALLOWED_KEYWORDS):
            continue
        text_blob = (step_kind or "") + " " + cmd
        if any(kw in text_blob.lower() for kw in _MASK_ALLOWED_KEYWORDS):
            continue
        m = _MASKED_FAILURE.search(cmd)
        if m:
            # For non-backup steps, masking failure defeats the rescan gate.
            # Report as warning — some legitimate uses exist (e.g. optional
            # cleanup after a scan) — so we surface but don't block.
            out.append(
                ValidationIssue(
                    check="masked_failure",
                    severity="warning",
                    message=(
                        f"step {si + 1} masks failure with {m.group(1)!r} — "
                        f"if this is a test/rescan/validation step, real "
                        f"failures will be hidden. Command: {cmd.strip()[:120]!r}"
                    ),
                    pathway_index=pi,
                    step_index=si,
                )
            )
    # Also inspect validation entries (structured tests). Note: `grep -c`
    # counting patterns legitimately use `|| true` to normalize grep's
    # "no match = nonzero exit" quirk — the count in stdout is the real
    # signal, not the exit code. Downgrade those to warning so real fixes
    # aren't blocked. True hidden failures (test command masked without
    # a counting pattern) stay as errors.
    for vi, test in enumerate(_iter_validation(pathway)):
        code = _step_command(test) or ""
        if not _MASKED_FAILURE.search(code):
            continue
        is_counting = bool(
            re.search(r"\bgrep\s+(?:-\S*c\S*|--count)\b", code) or re.search(r"\bwc\s+-l\b", code)
        )
        severity = "warning" if is_counting else "error"
        note = " (counting pattern — count is the signal, not exit code)" if is_counting else ""
        out.append(
            ValidationIssue(
                check="masked_failure",
                severity=severity,
                message=(
                    f"validation test #{vi + 1} masks failure{note}. Test: {code.strip()[:120]!r}"
                ),
                pathway_index=pi,
            )
        )
    return out


def _validate_rescan_cve_match(
    pathway: Any, pi: int, primary: dict, _family: str
) -> list[ValidationIssue]:
    """For CVE-typed findings, ensure at least one rescan/validation step
    actually greps for the SAME CVE id as the finding."""
    finding_cve = (primary.get("source_vuln_id") or "").strip()
    if not finding_cve.startswith("CVE-"):
        return []
    # Collect every CVE id mentioned in any test/validation/step command.
    seen: set[str] = set()
    for step in _iter_steps(pathway):
        cmd = _step_command(step) or ""
        seen.update(_CVE_ID.findall(cmd))
    for test in _iter_validation(pathway):
        cmd = _step_command(test) or ""
        seen.update(_CVE_ID.findall(cmd))
    if not seen:
        # No rescan against any CVE at all — not this validator's job to
        # flag missing rescans; the depth-guard warning covers that.
        return []
    if finding_cve not in seen:
        return [
            ValidationIssue(
                check="rescan_cve_mismatch",
                severity="error",
                message=(
                    f"finding is {finding_cve} but plan only rescans against "
                    f"{sorted(seen)[:5]}. Fix cannot be verified against the "
                    f"actual CVE."
                ),
                pathway_index=pi,
            )
        ]
    return []


_VALIDATORS = (
    _validate_no_op_sed,
    _validate_wrong_tool_for_family,
    _validate_masked_failure,
    _validate_rescan_cve_match,
)


# =============================================================================
# Duck-typed accessors — handle both Pydantic model and dict shape
# =============================================================================
def _iter_pathways(pkg: Any):
    pws = getattr(pkg, "pathways", None)
    if pws is None and isinstance(pkg, dict):
        pws = pkg.get("pathways")
    return pws or []


def _iter_steps(pathway: Any):
    steps = getattr(pathway, "remediation_steps", None)
    if steps is None and isinstance(pathway, dict):
        steps = pathway.get("remediation_steps")
    return steps or []


def _iter_validation(pathway: Any):
    tests = getattr(pathway, "validation_tests", None)
    if tests is None and isinstance(pathway, dict):
        tests = pathway.get("validation_tests") or pathway.get("test_scripts")
    return tests or []


def _step_command(step: Any) -> str:
    """Return the shell command for a step — schemas vary in field name."""
    for key in ("command", "code", "step", "action"):
        val = getattr(step, key, None)
        if val is None and isinstance(step, dict):
            val = step.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def _step_kind(step: Any) -> str:
    """Return a category / description string used for allowlisting checks."""
    for key in ("step_type", "type", "description", "kind"):
        val = getattr(step, key, None)
        if val is None and isinstance(step, dict):
            val = step.get(key)
        if isinstance(val, str):
            return val
    return ""
