"""Sub-Agent 4 shared types — Pydantic models used across orchestrator,
strategies, tools, safety, and persistence.

Design principle: these types ARE the interface between components. Everything
inside the fixer package that flows between two modules is a typed model
here, not a bare dict. The DB persists JSONB of these models' shapes so the
Python types and the SQL columns stay aligned by construction.

Nothing here contains strategy-specific fields. Family-agnostic vocabulary
so a future DependencyStrategy or CodeStrategy uses the exact same types.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Command-level results (what a single SSM RunCommand invocation produced)
# ============================================================================
class CommandResult(BaseModel):
    """Result of one shell command executed on env2 via SSM RunCommand.

    This is the atomic unit — every step, every validation test, every
    rollback command produces one of these. Persisted verbatim inside
    the higher-level step_result / validation_result JSONB fields.
    """

    model_config = ConfigDict(extra="forbid")

    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    started_at: datetime
    finished_at: datetime
    ssm_command_id: str | None = None  # for CloudTrail correlation

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


# ============================================================================
# Step-level results (one entry per remediation_step in the package)
# ============================================================================
class StepResult(BaseModel):
    """Result of executing one remediation_step from the package.

    Persisted as one entry in fix_runs.step_results (JSONB array).
    """

    model_config = ConfigDict(extra="forbid")

    step_num: int  # 1-indexed to match package.remediation_steps ordering
    action: str  # short human-readable label extracted from step.step's first line
    command: str  # the actual command that ran (may differ from package if LLM adapted)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    status: Literal["success", "failed", "skipped", "safety_blocked"]
    started_at: datetime
    finished_at: datetime
    ssm_command_id: str | None = None
    # If safety blocked the command, this is why
    safety_reason: str | None = None
    # If LLM adapted the command from what the package emitted
    adaptation_note: str | None = None


# ============================================================================
# Validation-level results (one entry per validation_test + the mandatory re-scan)
# ============================================================================
class ValidationResult(BaseModel):
    """Result of running one validation_test from the package.

    Persisted as one entry in fix_runs.validation_results (JSONB array).
    """

    model_config = ConfigDict(extra="forbid")

    test_name: str
    method: Literal["cli", "http", "sql", "manual"]
    command: str
    expected: str
    actual: str
    passed: bool
    duration_ms: int = 0
    # Whether this was the mandatory scanner re-scan (Nikhil's HARD RULE 17).
    # Exactly one validation per fix_run must have is_rescan=true.
    is_rescan: bool = False
    # For LLM-based semantic comparison (v1.4+), record the comparison basis
    comparison_note: str | None = None


# ============================================================================
# Rollback-level results
# ============================================================================
class RollbackResult(BaseModel):
    """Result of one rollback step. Same shape as StepResult but tagged."""

    model_config = ConfigDict(extra="forbid")

    step_num: int
    action: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    status: Literal["success", "failed"]
    started_at: datetime
    finished_at: datetime


# ============================================================================
# Backup / Preflight
# ============================================================================
class BackupResult(BaseModel):
    """Result of Phase A — the source-artifact snapshot before any edit."""

    model_config = ConfigDict(extra="forbid")

    backup_reference: str  # path to the .bak file or git branch name
    backup_type: Literal["file_copy", "git_branch", "state_snapshot", "none"]
    original_path: str | None = None
    created_at: datetime


class PreFlightResult(BaseModel):
    """Result of pre-flight checks before any command runs."""

    model_config = ConfigDict(extra="forbid")

    ready: bool
    checks: list[dict[str, Any]] = Field(default_factory=list)
    blocking_reason: str | None = None


# ============================================================================
# Safety module output
# ============================================================================
class SafetyResult(BaseModel):
    """Whether a specific command is safe to execute on env2."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str = ""
    matched_pattern: str | None = None  # which blocklist regex fired


# ============================================================================
# FixContext — everything the orchestrator hands to a strategy
# ============================================================================
class FixContext(BaseModel):
    """The bundle of state a strategy receives at invocation.

    Contains everything the strategy needs to plan + execute + validate +
    rollback for one package. Immutable during a run — mutable state (step
    results, timings) accumulates in FixRunState, not here.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    # Persistence handles
    fix_run_id: int
    package_id: int
    issue_id: int
    pathway_index: int
    agent_run_id: str

    # The package payload we're executing
    package: dict[str, Any]  # remediation_packages row (denormalized)
    pathway: dict[str, Any]  # package.pathways[pathway_index]

    # The originating issue (needed by LLM for context adaptation)
    issue: dict[str, Any]

    # IaC context extracted upstream by _extract_iac_context (see planner.py)
    file_path: str | None = None
    working_directory: str | None = None
    resource_name: str | None = None
    scanner_type: str | None = None  # 'iac' / 'sca' / 'sast' / 'os_pkg' / None

    # Target environment
    environment: Literal["sandbox", "production"] = "sandbox"
    target_instance_id: str
    aws_region: str = "us-east-1"

    # Populated by the orchestrator between phases so downstream methods
    # can reach earlier phases' output (e.g. rollback needs backup_reference
    # from backup()).
    backup_reference: str | None = None

    # Emitter — orchestrator injects the right trace emitter (real vs demo)
    # so strategies don't hardcode which schema they write to.
    # Signature: emit_fn(run_id: str, agent: str, event_type: str, message: str, payload: dict | None = None)


# ============================================================================
# Aggregated run outcome — what the strategy returns to the orchestrator
# ============================================================================
class StrategyOutcome(BaseModel):
    """Final outcome of a strategy's full lifecycle for one fix run."""

    model_config = ConfigDict(extra="forbid")

    # "partial_success" — batch mode outcome when SOME of the file's re-scan
    # tests pass and SOME fail. File is KEPT as-is (good edits preserved),
    # unfixed findings remain. Reported honestly instead of rolling everything
    # back to zero fixes.
    status: Literal["success", "partial_success", "failed", "rolled_back"]
    step_results: list[StepResult] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    rollback_results: list[RollbackResult] = Field(default_factory=list)
    backup_reference: str | None = None
    terraform_plan_output: str | None = None
    error_message: str | None = None
    error_step_number: int | None = None


# ============================================================================
# Helper: timestamp constructor for consistent timezone handling
# ============================================================================
def utcnow() -> datetime:
    """UTC-aware now(). Every model timestamp in this package uses this."""
    return datetime.now(UTC)
