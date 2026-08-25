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

from abc import ABC, abstractmethod
from typing import Any
from collections.abc import Callable

from ..models import (
    BackupResult,
    FixContext,
    PreFlightResult,
    RollbackResult,
    StepResult,
    ValidationResult,
)


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
