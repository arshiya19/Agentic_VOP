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

from ..models import (
    BackupResult,
    FixContext,
    PreFlightResult,
    RollbackResult,
    StepResult,
    ValidationResult,
)


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
