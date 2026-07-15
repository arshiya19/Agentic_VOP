"""fix_runs CRUD + status transition helpers.

Two schemas share the exact same table shape (public.fix_runs and
demo.fix_runs — see migration 0053). Callers select which by passing the
appropriate supabase client (`supabase_admin()` vs `supabase_admin_demo()`).

Nothing here knows about strategy internals. Persistence is pure DB-shape
translation — take a StrategyOutcome + FixContext, write a row.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from .models import (
    FixContext,
    StrategyOutcome,
    utcnow,
)


# =============================================================================
# INSERT — create fix_run at pending
# =============================================================================
def create_fix_run(
    sb: Any,
    *,
    package_id: int,
    issue_id: int,
    pathway_index: int,
    agent_run_id: str,
    strategy_key: str,
    environment: Literal["sandbox", "production"],
    target_instance_id: str | None,
    target_file_path: str | None,
    working_directory: str | None,
    timeout_seconds: int,
) -> int:
    """Insert a fix_run row in status='pending'. Return the new row id."""
    row = {
        "package_id": package_id,
        "issue_id": issue_id,
        "pathway_index": pathway_index,
        "agent_run_id": agent_run_id,
        "status": "pending",
        "strategy": strategy_key,
        "environment": environment,
        "target_instance_id": target_instance_id,
        "target_file_path": target_file_path,
        "working_directory": working_directory,
        "started_at": utcnow().isoformat(),
        "timeout_seconds": timeout_seconds,
    }
    resp = sb.table("fix_runs").insert(row).execute()
    rows = resp.data or []
    if not rows:
        raise RuntimeError("INSERT into fix_runs returned no row")
    return int(rows[0]["id"])


# =============================================================================
# UPDATE — status transitions
# =============================================================================
def set_status(
    sb: Any,
    fix_run_id: int,
    status: str,
    *,
    error_message: str | None = None,
    error_step_number: int | None = None,
) -> None:
    """Transition fix_run to a new status.

    Legal transitions match the CHECK on fix_runs.status. We don't enforce
    a state machine here — the DB rejects impossible transitions if the
    caller has bugs, and the orchestrator only makes legal transitions
    anyway.
    """
    patch: dict[str, Any] = {"status": status}
    if error_message is not None:
        patch["error_message"] = error_message[:2000]
    if error_step_number is not None:
        patch["error_step_number"] = error_step_number
    sb.table("fix_runs").update(patch).eq("id", fix_run_id).execute()


def set_backup_reference(sb: Any, fix_run_id: int, backup_reference: str) -> None:
    """Persist the backup path so rollback (later or from a different process)
    knows where to restore from."""
    sb.table("fix_runs").update({"backup_reference": backup_reference}).eq(
        "id", fix_run_id
    ).execute()


def set_terraform_plan_output(sb: Any, fix_run_id: int, plan_output: str) -> None:
    """Persist the raw `terraform plan` stdout for audit."""
    sb.table("fix_runs").update({"terraform_plan_output": plan_output[:100_000]}).eq(
        "id", fix_run_id
    ).execute()


# =============================================================================
# UPDATE — write the whole outcome at the end of a run
# =============================================================================
def finalize_fix_run(
    sb: Any,
    fix_run_id: int,
    *,
    ctx: FixContext,
    outcome: StrategyOutcome,
    started_at: datetime,
) -> None:
    """Write the final row shape at end-of-run.

    Called after the strategy returns (whether success, failed, or
    rolled_back). Persists all four JSONB arrays + terraform_plan +
    duration + final status.
    """
    finished_at = utcnow()
    duration_s = int((finished_at - started_at).total_seconds())

    patch: dict[str, Any] = {
        "status": outcome.status,
        "step_results": [r.model_dump(mode="json") for r in outcome.step_results],
        "validation_results": [r.model_dump(mode="json") for r in outcome.validation_results],
        "rollback_results": [r.model_dump(mode="json") for r in outcome.rollback_results],
        "rollback_triggered": len(outcome.rollback_results) > 0,
        "finished_at": finished_at.isoformat(),
        "duration_seconds": duration_s,
    }
    if outcome.backup_reference:
        patch["backup_reference"] = outcome.backup_reference
    if outcome.terraform_plan_output:
        patch["terraform_plan_output"] = outcome.terraform_plan_output[:100_000]
    if outcome.error_message:
        patch["error_message"] = outcome.error_message[:2000]
    if outcome.error_step_number is not None:
        patch["error_step_number"] = outcome.error_step_number

    # Also persist any updated file_path / working_directory the strategy
    # may have discovered (rare — mostly they come from ctx which was set
    # at INSERT time).
    if ctx.file_path:
        patch["target_file_path"] = ctx.file_path
    if ctx.working_directory:
        patch["working_directory"] = ctx.working_directory

    sb.table("fix_runs").update(patch).eq("id", fix_run_id).execute()


# =============================================================================
# READ — used by the /promote-to-prod endpoint (Phase-2 feature — not MVP)
# =============================================================================
def get_fix_run(sb: Any, fix_run_id: int) -> dict | None:
    """Fetch a fix_run row by id (for API endpoints + UI)."""
    resp = sb.table("fix_runs").select("*").eq("id", fix_run_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def any_concurrent_run(sb: Any) -> dict | None:
    """Return {id, status, package_id, started_at, updated_at} of any in-flight
    fix_run (status in the mutating set), or None if the fleet is idle.

    The orchestrator uses this to enforce single-run concurrency (Nikhil's
    architecture note: parallel runs would race on env2 + terraform state
    lock). MVP-safe conservative default.

    Returns the richer dict rather than just an id so caller error messages
    can name WHAT is in flight (which package, when it started, how long
    it's been running). Callers who only need the id can use `["id"]`.
    Returns None when nothing is in flight.
    """
    resp = (
        sb.table("fix_runs")
        .select("id, status, package_id, started_at, updated_at")
        .in_("status", ("pending", "provisioning", "executing", "validating"))
        .order("id", desc=False)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    return rows[0] if rows else None
