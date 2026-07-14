"""Sub-Agent 4 orchestrator — top-level, family-blind.

Loads a remediation_package, picks the right BaseFixStrategy subclass,
runs the 5-phase lifecycle (pre_flight → backup → execute → validate →
rollback-on-failure), and persists the outcome to fix_runs.

Zero strategy-specific logic here. Adding a new family later = new
BaseFixStrategy subclass + one line in the `_STRATEGY_BY_KEY` dispatch
map at the top of this file. Everything else stays untouched.

Two entry points:
  run_fixer(package_id, ...)      — used by API endpoint + auto-chain
  run_fixer_demo(package_id, ...) — same flow but on demo schema
"""

from __future__ import annotations

from typing import Any

from .config import FixerConfig, load_config_from_settings
from .models import (
    FixContext,
    StrategyOutcome,
    utcnow,
)
from .persistence import (
    any_concurrent_run,
    create_fix_run,
    finalize_fix_run,
    set_backup_reference,
    set_status,
    set_terraform_plan_output,
)
from .strategies.base import BaseFixStrategy
from .strategies.iac_strategy import IaCStrategy


# =============================================================================
# Strategy dispatch — one line per family. Genericity survives by this map
# being the ONLY place code branches on family/scanner_type.
# =============================================================================
_STRATEGY_BY_KEY: dict[str, type[BaseFixStrategy]] = {
    "iac": IaCStrategy,
    # Phase-2 additions land here:
    # "dependency": DependencyStrategy,
    # "code_edit":  CodeEditStrategy,
    # "cli":        CliStrategy,
}


# =============================================================================
# Family → strategy_key mapping.
#
# Family alone doesn't fully determine the strategy — a public_exposure
# finding on a Terraform-managed bucket goes 'iac', but the same family on
# a mutable direct-cloud bucket would go 'cli'. So we prefer scanner_type
# (from IaC context) with family as a secondary hint.
# =============================================================================
def _select_strategy_key(
    *,
    family: str,
    scanner_type: str | None,
) -> str:
    """Pick the fix strategy key based on scanner_type + family.

    Priority: scanner_type wins when known (SA3 v2.4 decided the shape of
    the package based on this). Family is a fallback for cases where
    scanner_type wasn't extractable.
    """
    if scanner_type in ("iac", "sca"):
        # SCA findings often ship with an IaC-shaped fix (edit manifest → install)
        # so they're handled by IaCStrategy in MVP too. Phase-2 introduces a
        # dedicated DependencyStrategy that reuses tools/ but adds pip/npm logic.
        return "iac"
    if scanner_type == "sast":
        # No CodeEditStrategy yet — MVP doesn't handle injection findings.
        # Return 'iac' as a best-effort; execution will likely fail on files
        # that aren't valid HCL, which is what we want (fail fast).
        return "iac"
    if scanner_type == "os_pkg":
        # DependencyStrategy will handle these post-MVP.
        return "iac"

    # Fallback: family-based dispatch when scanner_type wasn't extracted
    if family in ("public_exposure", "network_exposure"):
        return "iac"
    return "iac"  # MVP has only IaC; other cases will be added Phase-2+


# =============================================================================
# Public entry point
# =============================================================================
def run_fixer(
    package_id: int,
    *,
    agent_run_id: str,
    sb: Any,
    emit_fn,
    environment: str = "sandbox",
    config: FixerConfig | None = None,
) -> int:
    """Run Sub-Agent 4 against one remediation_package.

    Args:
        package_id:   which remediation_packages row to fix
        agent_run_id: for trace correlation (auto-chain populates this from
                      the SA3 run so events string together in the UI)
        sb:           supabase client (public.* or demo.* — determines which
                      fix_runs table gets written)
        emit_fn:      trace emitter (emit_trace for real, emit_trace_demo)
        environment:  'sandbox' (Phase-1 default) or 'production' (promote flow)
        config:       optional FixerConfig; loaded from settings if None

    Returns:
        The new fix_run id.

    Raises:
        RuntimeError — for setup failures the caller should log + move on.
        Strategy-level failures are captured in the fix_run row's status +
        error_message, not raised.
    """
    cfg = config or load_config_from_settings()

    # Concurrency lock — MVP runs one fix at a time (Nikhil's design note)
    if not FixerConfig.allow_concurrent_runs:
        other = any_concurrent_run(sb)
        if other is not None:
            raise RuntimeError(
                f"Another fix_run (#{other}) is currently in-flight. "
                "Sub-Agent 4 runs sequentially in MVP. Wait for it to complete "
                "or cancel it, then retry."
            )

    # 1. Load the package
    pkg_row = _load_package(sb, package_id)
    if pkg_row is None:
        raise RuntimeError(f"remediation_packages row #{package_id} not found")

    issue_id = int(pkg_row["issue_id"])
    family = pkg_row.get("family", "")
    pathway_index = int(pkg_row.get("recommended_pathway_index") or 0)
    pathways = pkg_row.get("pathways") or []
    if pathway_index >= len(pathways):
        raise RuntimeError(
            f"Package #{package_id} recommended_pathway_index {pathway_index} "
            f"out of range (only {len(pathways)} pathways)"
        )
    pathway = pathways[pathway_index]

    # 2. Load the issue (for IaC context — file_path / working_directory / etc.)
    issue_row = _load_issue(sb, issue_id)
    if issue_row is None:
        raise RuntimeError(f"issues row #{issue_id} not found")

    # 3. Extract IaC context (same helper SA3 used — single source of truth)
    from ..remediation.planner import _extract_iac_context  # noqa: PLC0415
    raw = _load_raw_finding(sb, issue_row.get("raw_finding_id"))
    iac_ctx = _extract_iac_context(issue_row, raw)

    # 4. Decide strategy
    strategy_key = _select_strategy_key(
        family=family, scanner_type=iac_ctx.get("scanner_type")
    )
    strategy_cls = _STRATEGY_BY_KEY.get(strategy_key)
    if strategy_cls is None:
        raise RuntimeError(
            f"No fix strategy registered for key {strategy_key!r} "
            f"(family={family}, scanner_type={iac_ctx.get('scanner_type')})"
        )

    # 5. Sanity: strategy needs a target instance to talk to
    target_instance_id = cfg.env2_instance_id or ""
    if not target_instance_id:
        raise RuntimeError(
            "FixerConfig.env2_instance_id is not set. Configure "
            "FIXER_ENV2_INSTANCE_ID in the app's environment before running SA4."
        )

    # 6. Create the fix_run row (status='pending')
    fix_run_id = create_fix_run(
        sb,
        package_id=package_id,
        issue_id=issue_id,
        pathway_index=pathway_index,
        agent_run_id=agent_run_id,
        strategy_key=strategy_key,
        environment=environment,  # type: ignore[arg-type]
        target_instance_id=target_instance_id,
        target_file_path=iac_ctx.get("file_path"),
        working_directory=iac_ctx.get("working_directory"),
        timeout_seconds=cfg.run_timeout_s,
    )

    emit_fn(
        agent_run_id,
        "sub-agent-4",
        "DISPATCH",
        f"🔧 Fix run #{fix_run_id} started — strategy={strategy_key}, "
        f"package=#{package_id}, family={family}, target={target_instance_id}",
    )

    # 7. Build ctx + strategy instance
    ctx = FixContext(
        fix_run_id=fix_run_id,
        package_id=package_id,
        issue_id=issue_id,
        pathway_index=pathway_index,
        agent_run_id=agent_run_id,
        package=pkg_row,
        pathway=pathway,
        issue=issue_row,
        file_path=iac_ctx.get("file_path"),
        working_directory=iac_ctx.get("working_directory"),
        resource_name=iac_ctx.get("resource_name"),
        scanner_type=iac_ctx.get("scanner_type"),
        environment=environment,  # type: ignore[arg-type]
        target_instance_id=target_instance_id,
        aws_region=cfg.aws_region,
    )
    strategy = strategy_cls(config=cfg, emit_fn=emit_fn)

    # 8. Execute lifecycle
    started_at = utcnow()
    outcome = _run_lifecycle(
        sb, fix_run_id, strategy, ctx, emit_fn=emit_fn
    )

    # 9. Persist final state
    finalize_fix_run(sb, fix_run_id, ctx=ctx, outcome=outcome, started_at=started_at)

    emit_fn(
        agent_run_id,
        "sub-agent-4",
        "DONE",
        f"🔧 Fix run #{fix_run_id} finished — status={outcome.status} "
        f"({len(outcome.step_results)} steps, {len(outcome.validation_results)} validations)",
        payload={
            "fix_run_id": fix_run_id,
            "status": outcome.status,
            "strategy": strategy_key,
        },
    )
    return fix_run_id


# =============================================================================
# Lifecycle — pre_flight → backup → execute → validate → maybe-rollback
# =============================================================================
def _run_lifecycle(
    sb: Any,
    fix_run_id: int,
    strategy: BaseFixStrategy,
    ctx: FixContext,
    *,
    emit_fn,
) -> StrategyOutcome:
    """Drive the 5 strategy phases. Returns a StrategyOutcome.

    Catches strategy-level exceptions and converts to 'failed' + rollback
    attempt. Never re-raises — the fix_run row captures everything the
    caller needs to know.
    """
    # ─── Phase 3: Pre-flight ────────────────────────────────────────────
    set_status(sb, fix_run_id, "provisioning")
    try:
        preflight = strategy.pre_flight_check(ctx)
    except Exception as e:  # noqa: BLE001
        return StrategyOutcome(
            status="failed",
            error_message=f"pre_flight raised {type(e).__name__}: {str(e)[:500]}",
        )
    if not preflight.ready:
        return StrategyOutcome(
            status="failed",
            error_message=preflight.blocking_reason or "pre_flight failed",
        )

    # ─── Phase 4: Backup ────────────────────────────────────────────────
    try:
        backup = strategy.backup(ctx)
    except Exception as e:  # noqa: BLE001
        return StrategyOutcome(
            status="failed",
            error_message=f"backup raised {type(e).__name__}: {str(e)[:500]}",
        )
    if backup.backup_reference:
        set_backup_reference(sb, fix_run_id, backup.backup_reference)
        # Immutable model → construct a fresh ctx with backup filled in.
        # Pydantic supports .model_copy for this.
        ctx = ctx.model_copy(update={"backup_reference": backup.backup_reference})

    # ─── Phase 5: Execute ───────────────────────────────────────────────
    set_status(sb, fix_run_id, "executing")
    try:
        step_results = strategy.execute(ctx)
    except Exception as e:  # noqa: BLE001
        # Terminal — try rollback
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=[],
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            error_message=f"execute raised {type(e).__name__}: {str(e)[:500]}",
        )

    # Persist terraform plan output when we can spot it (audit trail per Nikhil)
    plan_out = _extract_plan_output(step_results)
    if plan_out:
        set_terraform_plan_output(sb, fix_run_id, plan_out)

    # Any step failure → rollback
    failed_step = next(
        (r for r in step_results if r.status in ("failed", "safety_blocked")),
        None,
    )
    if failed_step is not None:
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=step_results,
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=(
                f"Step {failed_step.step_num} {failed_step.status}: "
                + (failed_step.safety_reason or failed_step.stderr[:300])
            ),
            error_step_number=failed_step.step_num,
        )

    # ─── Phase 6: Validate ──────────────────────────────────────────────
    set_status(sb, fix_run_id, "validating")
    try:
        validation_results = strategy.validate(ctx)
    except Exception as e:  # noqa: BLE001
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=step_results,
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=f"validate raised {type(e).__name__}: {str(e)[:500]}",
        )

    # Re-scan (mandatory per SA3 v2.4 hard rule 17) must pass. Other
    # validation failures also trigger rollback.
    rescan = next((v for v in validation_results if v.is_rescan), None)
    non_rescan_failures = [v for v in validation_results if not v.is_rescan and not v.passed]

    if rescan is not None and not rescan.passed:
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=step_results,
            validation_results=validation_results,
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=f"Scanner re-scan still reports the finding: {rescan.actual[:300]}",
        )

    if non_rescan_failures:
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=step_results,
            validation_results=validation_results,
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=(
                f"{len(non_rescan_failures)} validation test(s) failed — first: "
                f"{non_rescan_failures[0].test_name}"
            ),
        )

    # 🎉 Success
    return StrategyOutcome(
        status="success",
        step_results=step_results,
        validation_results=validation_results,
        backup_reference=backup.backup_reference,
        terraform_plan_output=plan_out,
    )


# =============================================================================
# Helpers
# =============================================================================
def _safe_rollback(strategy: BaseFixStrategy, ctx: FixContext, *, emit_fn) -> list:
    """Attempt rollback, swallowing exceptions so orchestrator finalization
    always runs. Returns whatever RollbackResult list the strategy produced
    (empty on total-failure)."""
    try:
        return strategy.rollback(ctx)
    except Exception as e:  # noqa: BLE001
        try:
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "ERROR",
                f"Rollback itself raised {type(e).__name__}: {str(e)[:300]}",
            )
        except Exception:  # noqa: BLE001, S110
            pass
        return []


def _extract_plan_output(step_results: list) -> str | None:
    """Find the `terraform plan` step's stdout and return it (for audit)."""
    for r in step_results:
        if "terraform plan" in (r.command or ""):
            return (r.stdout or "")[:100_000]
    return None


def _load_package(sb: Any, package_id: int) -> dict | None:
    resp = (
        sb.table("remediation_packages")
        .select("*")
        .eq("id", package_id)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    return rows[0] if rows else None


def _load_issue(sb: Any, issue_id: int) -> dict | None:
    resp = sb.table("issues").select("*").eq("id", issue_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def _load_raw_finding(sb: Any, raw_finding_id: int | None) -> dict | None:
    if raw_finding_id is None:
        return None
    resp = (
        sb.table("raw_findings")
        .select("raw")
        .eq("id", raw_finding_id)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    return (rows[0] or {}).get("raw") if rows else None
