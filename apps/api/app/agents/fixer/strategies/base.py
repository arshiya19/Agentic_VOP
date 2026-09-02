"""BaseFixStrategy — the abstract interface every fix strategy implements.

The 5-method shape (per Nikhil's 2026-07-13 architecture doc) is what
keeps the orchestrator family-blind:

  pre_flight_check(ctx) → PreFlightResult      Verify target ready
  backup(ctx)           → BackupResult         Snapshot for rollback
  execute(ctx)          → list[StepResult]     Apply the remediation
  validate(ctx)         → list[ValidationResult]  Test + re-scan
  rollback(ctx)         → list[RollbackResult] Restore pre-fix state

Adding a new family later = new subclass. Orchestrator doesn't change.
The methods return the persistence shapes from `models.py` directly, so
the orchestrator just needs to stitch them into a StrategyOutcome and
write to fix_runs — no per-family branching.

Strategies MAY raise exceptions to signal terminal failure; the
orchestrator catches, marks fix_run as 'failed', and triggers rollback.
Normal control flow (step failure, validation failure) is expressed by
returning results with status=failed / passed=False.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from ..models import (
    BackupResult,
    FixContext,
    PreFlightResult,
    RollbackResult,
    StepResult,
    ValidationResult,
)


# =============================================================================
# Shared skip-policy regexes — enforce the "static remediation" contract.
#
# The remediation service handles STATIC fixes (edit source, satisfy scanner).
# It does NOT deploy, mutate cloud resources, or perform runtime verification.
# Those belong to CI/CD and QA pipelines downstream. Every enterprise
# remediation platform (Snyk, Kenna, Seemplicity, Armorcode) enforces this
# separation — mixing them causes deploy failures to cascade as fix failures
# and forces the fix env to hold prod-tier IAM permissions.
#
# When a plan step matches either regex, the strategy SKIPS it. The scanner
# re-scan step (semgrep/checkov/trivy against the local file) is exempted by
# strategies via their own _looks_like_rescan check before consulting these.
# =============================================================================
CLOUD_DEPLOY_RE = re.compile(
    r"\b("
    # AWS CLI — mutations & deploys across compute / secrets / IAM / net
    r"aws\s+lambda\s+(update|create|delete|publish|add|remove)-|"
    r"aws\s+secretsmanager\s+(create|update|put|delete|restore|rotate)-|"
    r"aws\s+ssm\s+(put|delete|update)-parameter|"
    r"aws\s+iam\s+(create|delete|attach|detach|put|update|add|remove)-|"
    r"aws\s+ec2\s+(run|terminate|stop|start|create|delete|modify|attach|detach)-|"
    r"aws\s+ecs\s+(update|create|delete|register|deregister)-|"
    r"aws\s+eks\s+(update|create|delete|associate|disassociate)-|"
    r"aws\s+cloudformation\s+(deploy|update-stack|create-stack|delete-stack|execute-change-set)|"
    r"aws\s+s3api\s+(put|delete|create)-|"
    # IaC deploy
    r"terraform\s+(apply|destroy|import|taint)|"
    r"serverless\s+(deploy|remove)|"
    r"sam\s+(deploy|build|sync)|"
    r"cdk\s+(deploy|destroy|bootstrap)|"
    r"pulumi\s+(up|destroy|refresh)|"
    # Container / K8s deploy
    r"docker\s+(push|build|run|start)|"
    r"kubectl\s+(apply|create|delete|patch|edit|replace|rollout|scale)|"
    r"helm\s+(install|upgrade|uninstall|rollback)|"
    r"kustomize\s+(build|edit)|"
    # GCP & Azure equivalents
    r"gcloud\s+(functions|run|compute|iam|kms)\s+(deploy|create|update|delete)|"
    r"az\s+(functionapp|webapp|deployment|role|keyvault)\s+(create|update|deploy|delete)"
    r")\b",
    re.IGNORECASE,
)

CLOUD_RUNTIME_LOOKUP_RE = re.compile(
    r"\b("
    # Runtime secret / config retrieval — meaningful only after deploy
    r"aws\s+secretsmanager\s+get-secret-value|"
    r"aws\s+ssm\s+get-parameter|"
    # Any Lambda invoke/inspect on a deployed function.
    # `aws lambda get-function` and its `-configuration`/`-code`/`-policy`
    # variants all query deployed state — no signal for a static file fix.
    r"aws\s+lambda\s+(invoke|get-function(-code|-configuration|-policy|-url-config)?)|"
    r"aws\s+lambda\s+list-|"
    # GCP/Azure equivalents
    r"gcloud\s+secrets\s+versions\s+access|"
    r"gcloud\s+functions\s+call|"
    r"az\s+keyvault\s+secret\s+show|"
    r"az\s+functionapp\s+function\s+invoke"
    r")\b",
    re.IGNORECASE,
)


def runtime_lookup_skip_reason(command: str) -> str | None:
    """Return a skip reason if `command` matches a runtime-lookup pattern
    that any strategy's validate() phase should suppress.

    Runtime lookups (aws lambda invoke, aws secretsmanager get-secret-value,
    aws ssm get-parameter, aws lambda get-function-configuration, etc.)
    query the DEPLOYED state of AWS resources. They can never verify a
    static-file remediation:

      * They typically fail with AccessDenied on env2's locked-down role.
      * When they succeed, they measure the deployed runtime, not the
        edited source file — orthogonal to what SAST/IaC scanners judge.

    Applies universally across every strategy's validate() phase (iac,
    image, os, code_edit, dependency). Deploy verbs (terraform apply, aws
    lambda update-*, kubectl apply, etc.) are NOT skipped here because
    IaCStrategy legitimately runs them in execute() — that's a different
    hook (`_should_skip_shell_step` on CodeEditStrategy, applied to
    file-only strategies).

    Returns:
        str reason (LLM's plan wrote a runtime-lookup test — skip it)
        None (command isn't a runtime lookup — run it)
    """
    if CLOUD_RUNTIME_LOOKUP_RE.search(command):
        return (
            "validate phase skips runtime-lookup commands (aws secretsmanager "
            "get-secret-value, aws lambda invoke, aws ssm get-parameter, "
            "aws lambda get-function*, ...) — they query the DEPLOYED runtime, "
            "not the edited source file; scanner re-scan is authoritative"
        )
    return None


# =============================================================================
# Shared rescan-result matcher
# =============================================================================
def match_rescan_expected(expected: str, actual: str, exit_code: int) -> bool:
    """Correct comparator for scanner-rescan test outcomes.

    The scanner rescan pattern that SA-3 typically emits is:

        <scanner> ... | grep -c '<check_id>' || true

    * `grep -c` prints an integer count (0 = CVE gone, N>0 = still present).
    * `|| true` forces exit_code to 0 regardless of the count, so exit_code
      alone cannot be trusted to distinguish "fixed" from "not fixed".

    Historic bug (see os_strategy pre-2026-08-31): if `expected == "0"` was
    treated as "check exit_code == 0", the rescan always passed because `||
    true` masks the real result. Real successes and real failures both got
    credited as fixed.

    Semantics here:
      * Empty expected            → trust exit code (backward-compatible).
      * Numeric expected ("0", "3", ...) → strip actual and compare EXACTLY
        (this is the `grep -c` shape — the only correct read of the count).
      * Legacy exit-shape strings ("exit 0", "exit code 0", "command exits 0")
        → trust exit code (backward-compatible for tests written that way).
      * Any other expected string → substring match, with an exit_code == 0
        guard so a legit-crashed rescan doesn't silently "pass".

    No per-CVE, per-scanner, or per-family logic. Same rule for every strategy.
    """
    e = (expected or "").strip()
    if not e:
        return exit_code == 0
    # `grep -c` numeric count → exact match, tolerating scanner stderr noise.
    # Scanners like trivy emit INFO/WARN lines to stderr that some executors
    # merge into `actual`. grep -c's count is ALWAYS a single numeric-only
    # line — scan for the first such line and match against it. Never
    # substring "0" in "10" (false positive on any multi-digit count).
    if e.isdigit():
        for line in (actual or "").splitlines():
            stripped = line.strip()
            if stripped.isdigit():
                return stripped == e
        return False
    if e.lower() in ("command exits 0", "exit 0", "exit code 0"):
        return exit_code == 0
    # Text expected — substring match, but only when the command didn't crash.
    return exit_code == 0 and e in actual


# =============================================================================
# Shared pre-flight: tool availability
# =============================================================================
def verify_tools(
    executor: Any,
    tools: list[str],
    *,
    emit: Callable[[str, str], None] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Probe each tool with `<tool> --version 2>&1`. Return (checks, blocking_reason).

    Generic — no per-tool special-casing. Any CLI that responds to `--version`
    (pip, npm, docker, terraform, checkov, kubectl, mvn, ...) works. First
    tool that exits non-zero produces a blocking_reason; caller returns
    PreFlightResult(ready=False, ...) with it.

    Purpose: distinguish a broken execution environment (pip corrupt, docker
    daemon down) from a bad remediation plan. When a required tool is
    missing, the fix_run is marked failed at pre-flight with a clear
    error_message instead of running the whole plan and rolling back at
    Step 4 with a generic "exit status 1".
    """
    checks: list[dict[str, Any]] = []
    for tool in tools:
        try:
            r = executor.run_command(f"{tool} --version 2>&1", timeout_s=30)
            exit_code = r.exit_code
            output = ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:  # noqa: BLE001 — treat any probe error as tool-unavailable
            exit_code = -1
            output = f"probe raised {type(e).__name__}: {str(e)[:200]}"

        ok = exit_code == 0 and bool(output)
        checks.append(
            {"check": "tool_available", "tool": tool, "passed": ok, "exit_code": exit_code}
        )
        if emit is not None:
            if ok:
                first_line = output.splitlines()[0][:120]
                emit("MESSAGE", f"✓ Pre-flight: {tool} available ({first_line})")
            else:
                emit("ERROR", f"✗ Pre-flight: {tool} unavailable — {output[:180] or 'no output'}")
        if not ok:
            return checks, (
                f"Required tool {tool!r} is not usable on the target instance "
                f"(exit={exit_code}). Output: {output[:400] or '(empty)'}. "
                f"Fix the environment before re-running this remediation."
            )
    return checks, None


# =============================================================================
# The interface
# =============================================================================
class BaseFixStrategy(ABC):
    """Abstract base for every fix strategy.

    Contract:
      - Methods run in order: pre_flight → backup → execute → validate.
      - If pre_flight_check.ready is False, orchestrator halts and marks
        the fix_run failed with the blocking_reason.
      - If execute() returns any StepResult with status='failed', the
        orchestrator halts + triggers rollback.
      - If validate() returns any ValidationResult with passed=False, the
        orchestrator triggers rollback (unless all failures are the
        mandatory re-scan — which is treated as a definitive negative).
      - rollback() is called exactly when execute/validate report failure
        OR when the orchestrator catches an unhandled exception. It MUST
        be idempotent — safe to run even if backup was never taken.

    Strategies own their emit_fn calls for granular tracing. The
    orchestrator emits high-level lifecycle events (started, moved to
    validating, etc.); strategies emit per-step detail.
    """

    # Human-readable strategy name for logging + trace events. Subclasses
    # override with e.g. "IaC (Terraform)".
    name: str = "base"

    # The `strategy` value that gets persisted on fix_runs.strategy
    # (constrained by DB CHECK — see migration 0053).
    # Subclasses override with one of: iac / cli / dependency / code_edit.
    strategy_key: str = "base"

    # ============================================================================
    # Method contract
    # ============================================================================

    @abstractmethod
    def pre_flight_check(self, ctx: FixContext) -> PreFlightResult:
        """Verify env2 is reachable + required tools are installed + the
        target file/resource exists. Returns PreFlightResult.ready=False
        with a blocking_reason if any check fails.

        Non-failing side effects (e.g. `terraform init` if `.terraform/`
        missing) are acceptable here.
        """
        ...

    @abstractmethod
    def backup(self, ctx: FixContext) -> BackupResult:
        """Snapshot whatever the strategy needs to roll back to.

        For IaC: cp .tf → .tf.bak-{timestamp}. For code_edit: `git branch`
        or full-file backup. For dependency: manifest backup. Returns
        BackupResult with backup_reference — persisted on fix_run.
        """
        ...

    @abstractmethod
    def execute(self, ctx: FixContext) -> list[StepResult]:
        """Run the package's remediation_steps in order.

        Each StepResult must have status set. On the first failed step,
        strategy MAY early-return the results collected so far — the
        orchestrator will detect the failure and trigger rollback.
        """
        ...

    @abstractmethod
    def validate(self, ctx: FixContext) -> list[ValidationResult]:
        """Run the package's validation_tests + the mandatory scanner
        re-scan (SA3 v2.4 hard rule 17).

        Exactly one entry MUST have is_rescan=True. If the re-scan fails,
        rollback fires.
        """
        ...

    @abstractmethod
    def rollback(self, ctx: FixContext) -> list[RollbackResult]:
        """Restore the target to its pre-fix state.

        Called by the orchestrator on failure OR by the promote-to-prod
        UI if a prod fix run needs to be undone.

        Idempotent — safe to call even if backup() was never called
        successfully. In that case return an empty list.
        """
        ...

    # ============================================================================
    # Convenience — subclasses generally shouldn't override
    # ============================================================================

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__}(name={self.name!r})>"
