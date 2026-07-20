"""Terraform primitives via SSM RunCommand.

Wraps `terraform init / plan / apply` in typed operations that:
  - use the strategy's working directory
  - use per-action timeouts from FixerConfig (plan/apply take longer)
  - interpret `terraform plan -detailed-exitcode`'s three-state exit code
  - return the raw stdout so the caller can persist it in
    fix_runs.terraform_plan_output for audit

Non-goal: this file is NOT terraform-specific glue for public/network
findings. The IaCStrategy composes these primitives per Nikhil's flow.
Adding a new deploy tool (Pulumi, kustomize, ansible) later = new sibling
module (pulumi.py, kubectl.py, etc.) implementing the same shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..config import FixerConfig
from ..models import CommandResult
from .remote_exec import RemoteExecutor


# =============================================================================
# `terraform plan -detailed-exitcode` returns three legal values:
#   0 — no changes to apply (unexpected after an edit — likely edit didn't take)
#   1 — error (syntax, provider misconfig, state lock, credentials, etc.)
#   2 — changes detected (the expected state after an edit)
# =============================================================================
PlanOutcome = Literal["no_changes", "error", "changes_detected"]


@dataclass(frozen=True)
class PlanResult:
    """Structured Terraform plan outcome.

    Composed from the raw CommandResult so callers can persist the full
    plan text to fix_runs.terraform_plan_output for the human review.
    """

    outcome: PlanOutcome
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    command_result: CommandResult

    @property
    def is_ready_to_apply(self) -> bool:
        """True when plan showed pending changes cleanly (exit 2)."""
        return self.outcome == "changes_detected"


# =============================================================================
# init
# =============================================================================
def terraform_init(
    executor: RemoteExecutor,
    working_directory: str,
    *,
    config: FixerConfig,
    reconfigure: bool = False,
) -> CommandResult:
    """Run `terraform init` in the given directory.

    `reconfigure` triggers `-reconfigure` — needed when the backend config
    has changed (usually not the case for env2, whose backend is fixed by
    the Terraform files themselves).
    """
    reconfig_flag = " -reconfigure" if reconfigure else ""
    cmd = f"terraform init -no-color -input=false{reconfig_flag}"
    return executor.run_command(
        cmd,
        working_directory=working_directory,
        timeout_s=config.terraform_init_timeout_s,
    )


# =============================================================================
# plan
# =============================================================================
def terraform_plan(
    executor: RemoteExecutor,
    working_directory: str,
    *,
    config: FixerConfig,
) -> PlanResult:
    """Run `terraform plan -detailed-exitcode` and interpret the three-state
    exit code.

    Returns PlanResult with:
      - outcome           — 'changes_detected' (2, expected), 'no_changes' (0,
                            usually a bug: our edit didn't take), 'error' (1)
      - is_ready_to_apply — convenience bool = (outcome == 'changes_detected')
      - stdout            — full plan text for audit / for the LLM if it needs
                            to interpret an error

    We use `-no-color` and `-input=false` so the output is deterministic +
    parseable + doesn't hang waiting for interactive prompts.
    """
    cmd = "terraform plan -detailed-exitcode -no-color -input=false"
    result = executor.run_command(
        cmd,
        working_directory=working_directory,
        timeout_s=config.terraform_plan_timeout_s,
    )

    if result.exit_code == 0:
        outcome: PlanOutcome = "no_changes"
    elif result.exit_code == 2:
        outcome = "changes_detected"
    else:
        outcome = "error"

    return PlanResult(
        outcome=outcome,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_ms=result.duration_ms,
        command_result=result,
    )


# =============================================================================
# apply
# =============================================================================
def terraform_apply(
    executor: RemoteExecutor,
    working_directory: str,
    *,
    config: FixerConfig,
) -> CommandResult:
    """Run `terraform apply -auto-approve`. Caller MUST have run a successful
    plan first — apply without a preceding plan is refused by our flow.

    `-auto-approve` is acceptable here because:
      1. The plan (previous step) already validated the change set.
      2. This runs on env2 sandbox, not directly on prod (prod runs are a
         separate fix_run with a `Promote to Prod` human click gating them).
    """
    cmd = "terraform apply -auto-approve -no-color -input=false"
    return executor.run_command(
        cmd,
        working_directory=working_directory,
        timeout_s=config.terraform_apply_timeout_s,
    )


# =============================================================================
# state pull (for backup — capture current state before mutation)
# =============================================================================
def terraform_state_pull(
    executor: RemoteExecutor,
    working_directory: str,
    *,
    config: FixerConfig,
) -> CommandResult:
    """Run `terraform state pull` — emits the current state JSON on stdout.

    Callers persist the output to a backup file so rollback can restore
    the pre-fix state in the rare case that `terraform apply` succeeded
    but a subsequent step failed and simple .bak restore + apply isn't
    enough.
    """
    cmd = "terraform state pull"
    return executor.run_command(
        cmd,
        working_directory=working_directory,
        timeout_s=config.terraform_init_timeout_s,  # short op
    )


# =============================================================================
# version probe (pre-flight)
# =============================================================================
def terraform_version(executor: RemoteExecutor) -> CommandResult:
    """Return the terraform version on env2. Used by pre_flight_check to
    confirm terraform is actually installed."""
    return executor.run_command("terraform version -json")
