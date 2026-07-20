"""Sub-Agent 4 configuration — timeouts, retry limits, target selection.

All settings pulled from `app.config.settings` (env-backed) with sane defaults
so the fixer works in dev/demo without extra env setup.

Config knobs are here (not in-line as magic numbers) so we can tune them
per-environment (staging cranks up timeouts, prod tightens safety margins,
tests use zeros) without touching orchestration logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class FixerConfig:
    """Immutable fixer configuration snapshot for one run.

    Defaults are sensible for MVP demos against env2. Override per-call by
    constructing a new FixerConfig with different values.
    """

    # ─── Per-step SSM RunCommand timeout ──────────────────────────────────
    # How long a single remote command may run before we cancel it.
    # 60s handles `terraform plan`/`apply` on the small cspm-lab fixture.
    # Bump for larger IaC repos or slower networks.
    ssm_command_timeout_s: int = 120

    # ─── Whole-run timeout ────────────────────────────────────────────────
    # How long the entire fix (all steps + validation + rollback) may take.
    # Persisted on fix_runs.timeout_seconds for downstream monitors.
    run_timeout_s: int = 300

    # ─── SSM invocation polling ───────────────────────────────────────────
    # How often we poll ssm.get_command_invocation for terminal status.
    ssm_poll_interval_s: float = 2.0

    # ─── Terraform action timeouts ────────────────────────────────────────
    # Applied to the RunCommand invocation for terraform ops. Terraform can
    # be slower than a plain aws-cli call — give it more headroom.
    terraform_plan_timeout_s: int = 180
    terraform_apply_timeout_s: int = 300
    terraform_init_timeout_s: int = 120

    # ─── Re-scan (validation) timeout ─────────────────────────────────────
    # Scanner re-runs (checkov/trivy/semgrep) can be slow on medium repos.
    rescan_timeout_s: int = 180

    # ─── Retry policy ─────────────────────────────────────────────────────
    # Per-step retry count for transient SSM errors (throttling, agent
    # briefly unreachable). Application-level errors (non-zero exit code
    # from the actual command) are NEVER auto-retried — those go to the
    # LLM error-interpretation path.
    ssm_transient_retries: int = 2
    ssm_retry_backoff_s: float = 3.0

    # ─── Target environment ───────────────────────────────────────────────
    # env2 (Remediation Playground) instance ID + region. Sourced from
    # settings in production; hardcoded fallback for dev. Set via env:
    #   FIXER_ENV2_INSTANCE_ID  (e.g. "i-0abc1234def5678")
    #   FIXER_ENV2_REGION       (e.g. "us-east-1")
    env2_instance_id: str | None = None
    aws_region: str = "us-east-1"

    # ─── SSM document ─────────────────────────────────────────────────────
    # AWS-managed document that runs shell commands on Linux. We don't
    # ship a custom SSM document — the built-in one is sufficient for
    # `bash -c "..."` execution.
    ssm_document_name: str = "AWS-RunShellScript"

    # ─── Terraform state backend ──────────────────────────────────────────
    # env2's terraform is configured to store state in this S3 bucket +
    # lock via this DynamoDB table. We don't manage these here — env2's
    # terraform init points at them. Just tracked so error messages can
    # be specific if state is misconfigured.
    terraform_state_bucket: str = "sisyfix-terraform-state"
    terraform_lock_table: str = "sisyfix-terraform-locks"

    # ─── LLM model + params for SA4 ───────────────────────────────────────
    # Overridable via prompt_db.parameters at load time — these are the
    # code-side defaults if the DB row doesn't specify.
    default_model: str = "gpt-4o"
    default_temperature: float = 0.1  # low = deterministic command emission
    default_max_tokens: int = 2000

    # ─── Concurrency lock ─────────────────────────────────────────────────
    # We deliberately do NOT run multiple fixer runs in parallel in MVP —
    # they share the same env2 host + terraform state, so parallel runs
    # would race. Enforced at the orchestrator level via a DB check on
    # any other fix_run in status 'executing'/'provisioning'/'applying'.
    allow_concurrent_runs: ClassVar[bool] = False


def load_config_from_settings() -> FixerConfig:
    """Build a FixerConfig from `app.config.settings`.

    Kept as a function (not a module-level constant) so tests can construct
    isolated configs without touching global state. Real code paths call
    this at orchestrator startup to snapshot the current env.
    """
    # Deferred import — the fixer package must not force settings to load
    # on import (unit tests + tools want to import config.py cheaply).
    from ...config import settings

    return FixerConfig(
        env2_instance_id=getattr(settings, "fixer_env2_instance_id", None),
        aws_region=getattr(settings, "aws_region", "us-east-1"),
    )
