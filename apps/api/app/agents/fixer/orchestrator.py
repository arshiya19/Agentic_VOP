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
from .preflight import run_preflight_rewrite
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
from .strategies.image_strategy import ImageStrategy


# =============================================================================
# Strategy dispatch — one line per family. Genericity survives by this map
# being the ONLY place code branches on family/scanner_type.
# =============================================================================
_STRATEGY_BY_KEY: dict[str, type[BaseFixStrategy]] = {
    "iac": IaCStrategy,
    "image": ImageStrategy,  # trivy-image (container image OS pkgs)
    # Phase-2 additions land here:
    # "os":         OSStrategy,           # trivy-os / tenable (host apt/yum)
    # "dependency": DependencyStrategy,   # trivy-fs / snyk-appsec (app pkgs)
    # "code_edit":  CodeEditStrategy,     # semgrep / bandit (source edits)
    # "cli":        CliStrategy,          # aws-cli direct cloud fixes
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
    source: str | None = None,
) -> str:
    """Pick the fix strategy key based on source + scanner_type + family.

    Priority order (most specific → least specific):
      1. Source name — deterministic when we know the scanner. Container
         image scanners → image; host OS scanners → os.
      2. scanner_type from SA-3's extractor (iac / sast / sca / os_pkg).
      3. Family as a final fallback.

    Returns an unregistered key when no strategy is wired for the shape;
    run_fixer's dispatch check will surface a clean "no strategy registered"
    error rather than routing the fix to the wrong executor and corrupting
    env2.
    """
    src = (source or "").lower()

    # ---- Source-first routing ----
    # Container image scanners → ImageStrategy (docker rebuild + retag)
    if "trivy-image" in src or "snyk-container" in src or "grype-image" in src:
        return "image"
    # Host OS scanners → OSStrategy (apt/yum upgrade) — not yet registered
    if (
        "trivy-os" in src
        or "tenable-nessus" in src
        or "qualys-vmdr" in src
        or "rapid7" in src
    ):
        return "os"
    # App-dep scanners → DependencyStrategy — not yet registered
    if "trivy-fs" in src or "snyk-appsec" in src or "dependabot" in src or src == "osv":
        return "dependency"
    # SAST scanners → CodeEditStrategy — not yet registered
    if "semgrep" in src or "bandit" in src or "sonarqube" in src:
        return "code_edit"

    # ---- Family-based routing when source didn't decide ----
    if family == "os_vulnerability":
        # Family-only signal is ambiguous (image vs host). Prefer image
        # for MVP since trivy-image is the primary demo path; the source
        # branch above handles the disambiguation cleanly.
        return "image"
    if family == "vulnerable_dependency":
        return "dependency"  # not yet registered
    if family == "injection":
        return "code_edit"  # not yet registered

    # ---- scanner_type from IaC extractor ----
    if scanner_type in ("iac", "sca"):
        # SCA findings often ship with an IaC-shaped fix (edit manifest → install)
        # so they're handled by IaCStrategy in MVP too. Phase-2 introduces a
        # dedicated DependencyStrategy that reuses tools/ but adds pip/npm logic.
        return "iac"
    if scanner_type == "sast":
        return "code_edit"
    if scanner_type == "os_pkg":
        return "os"

    # Fallback: family-based dispatch when scanner_type wasn't extracted
    if family in ("public_exposure", "network_exposure"):
        return "iac"
    return "iac"  # Default to IaC for unknown shapes (matches historical behavior)


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

    # Concurrency lock — env2 is a single shared sandbox; only one fix_run
    # at a time (Nikhil's design note: parallel runs race on terraform state
    # + AWS API rate limits). Wait with backoff when locked rather than
    # raising immediately, so teammates iterating together don't step on
    # each other's dispatches.
    if not FixerConfig.allow_concurrent_runs:
        import time  # noqa: PLC0415 — local import; keeps top-of-file clean

        LOCK_WAIT_MAX_S = 300  # 5 min total wait
        LOCK_POLL_INTERVAL_S = 10
        waited_s = 0
        other = any_concurrent_run(sb)
        first_wait_notice_sent = False

        while other is not None and waited_s < LOCK_WAIT_MAX_S:
            if not first_wait_notice_sent:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⏳ env2 shared sandbox is busy — another fix_run "
                    f"(#{other['id']}, package #{other['package_id']}, "
                    f"status={other['status']}, started {other.get('started_at', '?')[:19]}) "
                    f"is active. Waiting up to {LOCK_WAIT_MAX_S}s for it to complete "
                    f"before dispatching this run…",
                )
                first_wait_notice_sent = True
            time.sleep(LOCK_POLL_INTERVAL_S)
            waited_s += LOCK_POLL_INTERVAL_S
            other = any_concurrent_run(sb)

        if other is not None:
            raise RuntimeError(
                f"env2 shared sandbox is still busy after waiting {waited_s}s. "
                f"Another user's fix_run (#{other['id']}, package "
                f"#{other['package_id']}, status={other['status']}, started "
                f"{other.get('started_at', '?')[:19]}) has been running for a long "
                f"time. env2 supports one fix at a time — coordinate with "
                f"whoever is running the other demo, wait a few more minutes, "
                f"then retry. Run `python scripts/check_env2_status.py` from "
                f"apps/api to see live state."
            )

        if waited_s > 0:
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"✓ env2 lock released after {waited_s}s wait — dispatching now.",
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

    # 4. Decide strategy — source name is the strongest signal for
    #    disambiguating trivy-image (ImageStrategy) vs trivy-os (OSStrategy)
    #    when both classify as family='os_vulnerability'.
    strategy_key = _select_strategy_key(
        family=family,
        scanner_type=iac_ctx.get("scanner_type"),
        source=issue_row.get("source"),
    )
    strategy_cls = _STRATEGY_BY_KEY.get(strategy_key)
    if strategy_cls is None:
        raise RuntimeError(
            f"No fix strategy registered for key {strategy_key!r} "
            f"(family={family}, scanner_type={iac_ctx.get('scanner_type')}, "
            f"source={issue_row.get('source')!r})"
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

    # 8. Execute lifecycle — wrapped in try/finally so ANY internal bug
    # (bad emit_fn signature, LLM crash, unexpected exception) still results
    # in fix_run being finalized. A crashed run left in 'in_flight' state
    # locks the concurrency check and blocks every subsequent fix — worse
    # than the original bug. Better to record a 'failed' outcome and move on.
    started_at = utcnow()
    outcome: StrategyOutcome
    try:
        outcome = _run_lifecycle(sb, fix_run_id, strategy, ctx, emit_fn=emit_fn)
    except Exception as e:  # noqa: BLE001
        # Belt-and-suspenders: _run_lifecycle already catches strategy-level
        # errors; this catches orchestrator-level bugs (bad emit call, etc.).
        # Fabricate a failed outcome so finalize_fix_run has something to persist.
        outcome = StrategyOutcome(
            status="failed",
            error_message=(
                f"orchestrator crashed: {type(e).__name__}: {str(e)[:400]} "
                f"(fix_run finalized as 'failed' to release concurrency lock)"
            ),
        )
        # Best-effort trace — swallow secondary errors so nothing here can
        # prevent finalize_fix_run from running.
        try:
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "ERROR",
                f"✗ Fix run #{fix_run_id} crashed mid-lifecycle: "
                f"{type(e).__name__}: {str(e)[:300]} — finalizing as failed",
            )
        except Exception:  # noqa: BLE001, S110
            pass

    # 9. Persist final state — MUST run so 'in_flight' status is cleared.
    # If finalize itself crashes there's not much we can do, but at least the
    # lifecycle exception path above will have produced a StrategyOutcome.
    try:
        finalize_fix_run(sb, fix_run_id, ctx=ctx, outcome=outcome, started_at=started_at)
    except Exception as e:  # noqa: BLE001
        try:
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "ERROR",
                f"✗ finalize_fix_run crashed for fix_run #{fix_run_id}: "
                f"{type(e).__name__}: {str(e)[:300]}. Row may remain 'in_flight' — "
                f"manual DB fix required.",
            )
        except Exception:  # noqa: BLE001, S110
            pass
        raise

    # 10. Knowledge Base capture — store successful fixes for future few-shot reuse.
    # Best-effort: never blocks the main flow. Only fires on verified success.
    # NOTE: Always writes to the PUBLIC schema — the KB is a shared knowledge
    # base that feeds SA-3 across all pipelines (real + demo). The `sb` passed
    # to run_fixer may be a demo-schema client, so we use a fresh public client.
    if outcome.status == "success":
        try:
            from ..remediation.kb_capture import capture_successful_fix  # noqa: PLC0415
            from ...db import supabase_admin as _kb_admin  # noqa: PLC0415

            kb_id = capture_successful_fix(
                _kb_admin(),
                ctx=ctx,
                outcome=outcome,
                confidence_score=(ctx.pathway or {}).get("confidence_score") or 90,
                emit_fn=emit_fn,
            )
            try:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"📚 KB capture result: kb_id={kb_id} (None = skipped/guard)",
                )
            except Exception:  # noqa: BLE001, S110
                pass
        except Exception as e:  # noqa: BLE001
            try:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "ERROR",
                    f"📚 KB capture FAILED: {type(e).__name__}: {str(e)[:300]}",
                )
            except Exception:  # noqa: BLE001, S110
                pass

    # 11. KB reuse tracking — if this fix used a KB replay recipe, update counters.
    # Increment times_reused (always after completion) and times_succeeded (on success).
    # This feeds the success_rate computed column for recipe quality monitoring.
    try:
        pathway_conf = (ctx.pathway or {}).get("confidence_components") or {}
        kb_source_id = (
            pathway_conf.get("kb_id") if pathway_conf.get("source") == "kb_replay" else None
        )
        if kb_source_id:
            from ..remediation.kb_capture import increment_reuse_count, increment_success_count  # noqa: PLC0415
            from ...db import supabase_admin as _kb_admin_fn  # noqa: PLC0415

            _kb_sb = _kb_admin_fn()
            increment_reuse_count(_kb_sb, kb_source_id)
            if outcome.status == "success":
                increment_success_count(_kb_sb, kb_source_id)
            try:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"📚 KB reuse tracked: kb_id={kb_source_id}, "
                    f"outcome={outcome.status} "
                    f"(times_reused +1{', times_succeeded +1' if outcome.status == 'success' else ''})",
                )
            except Exception:  # noqa: BLE001, S110
                pass
    except Exception:  # noqa: BLE001, S110
        pass  # Best-effort — never block main flow

    # Best-effort trace — a crash here doesn't affect persisted state.
    try:
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
    except Exception:  # noqa: BLE001, S110
        pass

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

    # ─── Phase 3.5: Pre-flight LLM rewriter ─────────────────────────────
    # Snapshot env2 (IAM identity + attached policies + terraform state) and
    # ask an LLM whether any remediation_steps will fail given that state.
    # High-confidence rewrites are applied to a fresh pathway copy; the
    # rewriter never modifies steps directly and always fail-opens on any
    # error (returns the original pathway unchanged). See preflight.py for
    # the full design.
    #
    # The canonical case this catches: SA3 emits `sse_algorithm = "aws:kms"`
    # for S3 encryption but env2 lacks kms:CreateKey — rewriter swaps to
    # AES256 which needs zero permissions.
    try:
        rewritten_pathway, rewrite_log = run_preflight_rewrite(ctx, emit_fn)
        if rewrite_log:
            # ctx is immutable Pydantic; construct a copy with the rewritten
            # pathway so downstream phases execute the modified package.
            ctx = ctx.model_copy(update={"pathway": rewritten_pathway})
    except Exception as e:  # noqa: BLE001
        # Belt-and-suspenders — run_preflight_rewrite already fail-opens
        # internally, but if something upstream (import, module-level state)
        # ever breaks, we still fall through to execute the original package.
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Pre-flight rewriter wrapper crashed ({type(e).__name__}: "
            f"{str(e)[:200]}) — executing original package.",
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

    # Step failure handling — context-aware rollback decision.
    #
    # If a step fails BEFORE terraform apply has succeeded, the fix hasn't
    # been committed to infrastructure yet → rollback immediately (safe,
    # nothing to undo except the file edit which the .bak handles).
    #
    # If a step fails AFTER terraform apply succeeded, the IaC change is
    # already live. Post-apply steps are typically verification commands
    # (aws CLI checks, IAM probes, etc.) that can fail for reasons unrelated
    # to whether the fix actually worked (missing IAM permission, empty
    # variable, broken awk pattern). Rolling back a successful apply because
    # a post-apply CLI check is broken is counterproductive — it destroys a
    # valid fix. Instead: log the failure as a warning and proceed to the
    # validation phase where the scanner re-scan (the authoritative proof)
    # will determine whether the fix actually worked.
    #
    # This mirrors the validation phase's existing "re-scan is authoritative"
    # logic — ancillary failures don't override a passing re-scan.
    failed_step = next(
        (r for r in step_results if r.status in ("failed", "safety_blocked")),
        None,
    )
    if failed_step is not None:
        # Determine if terraform apply already succeeded in an earlier step.
        # We check for any step with "terraform apply" in its command that
        # exited successfully (exit_code 0).
        apply_succeeded = any(
            "terraform apply" in (r.command or "") and r.status == "success" for r in step_results
        )

        if apply_succeeded:
            # Post-apply failure — the fix is live. Log warning, proceed to
            # validation. The re-scan will be the authoritative judge.
            try:
                emit_fn(
                    ctx.agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Step {failed_step.step_num} failed AFTER terraform apply "
                    f"succeeded — treating as non-critical warning. "
                    f"Proceeding to validation (re-scan will determine outcome). "
                    f"Failed step: {failed_step.action[:100]} | "
                    f"Error: {(failed_step.safety_reason or failed_step.stderr[:150])}",
                )
            except Exception:  # noqa: BLE001, S110
                pass
            # Fall through to the validation phase below — do NOT rollback
        else:
            # Pre-apply failure — fix was never committed. Rollback is safe.
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

    # Rollback decision policy:
    #   - Scanner re-scan is the AUTHORITATIVE proof of fix (Checkov / Trivy /
    #     Semgrep etc. re-run on the same file, filtered to the same check).
    #     If it passes, the vulnerability is objectively closed. Ancillary
    #     CLI checks (aws s3api get-*, describe-*) are supplementary — useful
    #     for the trace but they can fail for reasons unrelated to whether
    #     the fix worked (unset shell var, missing IAM permission, output
    #     format shift). Rolling back a confirmed fix because of a supplementary
    #     check failure defeats the whole point of the closed loop.
    #   - Absent a scanner re-scan (SA3 v2.4 hard rule 17 violation), fall
    #     back to strict mode: any non-rescan failure triggers rollback.
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
        if rescan is not None and rescan.passed:
            # Scanner re-scan authoritatively confirmed the fix. Log the
            # ancillary CLI failures as warnings and mark the run successful.
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"⚠ {len(non_rescan_failures)} ancillary validation test(s) failed "
                f"but scanner re-scan passed — fix confirmed by authoritative check. "
                f"Warnings preserved in validation_results for review. First warning: "
                f"{non_rescan_failures[0].test_name}",
            )
            # Fall through to success
        else:
            # No re-scan emitted — strict mode. Ancillary failures trigger rollback.
            rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
            return StrategyOutcome(
                status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
                step_results=step_results,
                validation_results=validation_results,
                rollback_results=rollback,
                backup_reference=backup.backup_reference,
                terraform_plan_output=plan_out,
                error_message=(
                    f"{len(non_rescan_failures)} validation test(s) failed "
                    f"(no scanner re-scan present to authoritatively confirm fix) — "
                    f"first failure: {non_rescan_failures[0].test_name}"
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
    resp = sb.table("remediation_packages").select("*").eq("id", package_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def _load_issue(sb: Any, issue_id: int) -> dict | None:
    resp = sb.table("issues").select("*").eq("id", issue_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def _load_raw_finding(sb: Any, raw_finding_id: int | None) -> dict | None:
    if raw_finding_id is None:
        return None
    resp = sb.table("raw_findings").select("raw").eq("id", raw_finding_id).limit(1).execute()
    rows = resp.data or []
    return (rows[0] or {}).get("raw") if rows else None
