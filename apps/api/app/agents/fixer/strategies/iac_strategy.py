"""IaCStrategy — Phase-1 concrete strategy for IaC-managed findings.

Implements Nikhil's 2026-07-13 flow for Checkov / Prisma / Trivy-config
findings on Terraform-managed resources:

  pre_flight → backup → execute (edit + plan + apply) → validate (test + re-scan)
                                                     ↘ rollback (restore + apply)

Design principles held here:
  1. GENERIC EXECUTION — no hardcoding of check IDs, resource types, or
     scanner names. All family-specific knowledge lives in the package
     that SA3 produced.
  2. STRICT COMMAND PROVENANCE — every command that runs on env2 was
     emitted BY SA3 into the package's remediation_steps. IaCStrategy
     never invents commands (except for the mechanical backup + restore
     inside backup()/rollback(), which are family-agnostic primitives).
  3. SAFETY BEFORE DISPATCH — every command passes safety.validate_command
     before SSM sees it.
  4. TRACE-ALL — the strategy emits one trace event per phase transition
     and per step for UI live-view.
"""

from __future__ import annotations

from typing import Any

from ...remediation.verifier import _extract_shell_blocks
from ..config import FixerConfig
from ..models import (
    BackupResult,
    FixContext,
    PreFlightResult,
    RollbackResult,
    StepResult,
    ValidationResult,
    utcnow,
)
from ..safety import validate_command
from ..tools.file_ops import (
    backup_file,
    file_exists,
    restore_from_backup,
)
from ..tools.remote_exec import (
    CommandTimeoutError,
    RemoteExecError,
    RemoteExecutor,
)
from ..tools.terraform import (
    terraform_apply,
    terraform_init,
    terraform_plan,
    terraform_version,
)
from .base import BaseFixStrategy


# =============================================================================
# Scanner CLI markers — used to detect "which validation_test is the re-scan"
# (per SA3 v2.4 hard rule 17: exactly one validation_test invokes the ORIGINAL
# scanner). Detection is by CLI verb only — no per-scanner logic anywhere.
# =============================================================================
_SCANNER_CLI_VERBS: tuple[str, ...] = (
    "checkov",
    "trivy",
    "semgrep",
    "bandit",
    "tfsec",
    "kics",
    "terrascan",
    "snyk",
    "grype",
    "sonar-scanner",
    "sonarqube",
    "prisma-cloud-scanner",
)


class IaCStrategy(BaseFixStrategy):
    """Strategy for IaC-managed findings (Checkov / Prisma / Trivy-config).

    Handles the six-phase flow universally — SA3's package tells us
    WHAT to do; this strategy just executes it correctly + safely.
    """

    name = "IaC (Terraform)"
    strategy_key = "iac"

    def __init__(
        self,
        *,
        config: FixerConfig,
        emit_fn,
    ) -> None:
        self.config = config
        self.emit_fn = emit_fn

    # =========================================================================
    # Phase 3 — Pre-flight
    # =========================================================================
    def pre_flight_check(self, ctx: FixContext) -> PreFlightResult:
        checks: list[dict[str, Any]] = []
        executor = self._executor_for(ctx)

        # 1. SSM connectivity
        reachable = executor.is_reachable()
        checks.append({"check": "ssm_reachable", "passed": reachable})
        if not reachable:
            reason = (
                f"env2 instance {ctx.target_instance_id!r} is not reachable "
                "via SSM. Verify the instance is running + SSM agent is up."
            )
            self._emit(ctx, "ERROR", f"✗ Pre-flight: {reason}")
            return PreFlightResult(ready=False, checks=checks, blocking_reason=reason)
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: SSM reachable")

        # 2. Target file exists (if the package declares one)
        if ctx.file_path:
            exists = file_exists(executor, ctx.file_path)
            checks.append(
                {
                    "check": "target_file_exists",
                    "passed": exists,
                    "file_path": ctx.file_path,
                }
            )
            if not exists:
                reason = (
                    f"Target file {ctx.file_path!r} not present on "
                    f"instance {ctx.target_instance_id!r}. Cannot proceed with IaC edit."
                )
                self._emit(ctx, "ERROR", f"✗ Pre-flight: {reason}")
                return PreFlightResult(ready=False, checks=checks, blocking_reason=reason)
            self._emit(ctx, "MESSAGE", f"✓ Pre-flight: {ctx.file_path} present")

        # 3. Terraform available
        tf_probe = terraform_version(executor)
        checks.append(
            {
                "check": "terraform_available",
                "passed": tf_probe.succeeded,
                "detail": tf_probe.stdout[:200] if tf_probe.succeeded else tf_probe.stderr[:200],
            }
        )
        if not tf_probe.succeeded:
            reason = (
                "terraform not available on env2 (or returned error). "
                f"stderr: {tf_probe.stderr[:200]}"
            )
            self._emit(ctx, "ERROR", f"✗ Pre-flight: {reason}")
            return PreFlightResult(ready=False, checks=checks, blocking_reason=reason)
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: terraform binary present")

        # 4. Terraform init if working directory not yet initialized
        if ctx.working_directory:
            init_marker = file_exists(
                executor, f"{ctx.working_directory}/.terraform/terraform.tfstate"
            )
            if not init_marker:
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"→ Pre-flight: running `terraform init` in {ctx.working_directory}",
                )
                init_result = terraform_init(executor, ctx.working_directory, config=self.config)
                checks.append(
                    {
                        "check": "terraform_init",
                        "passed": init_result.succeeded,
                        "duration_ms": init_result.duration_ms,
                    }
                )
                if not init_result.succeeded:
                    reason = (
                        f"terraform init failed in {ctx.working_directory!r}. "
                        f"stderr: {init_result.stderr[:400]}"
                    )
                    self._emit(ctx, "ERROR", f"✗ Pre-flight: {reason}")
                    return PreFlightResult(ready=False, checks=checks, blocking_reason=reason)

        return PreFlightResult(ready=True, checks=checks)

    # =========================================================================
    # Phase 4 — Backup
    # =========================================================================
    def backup(self, ctx: FixContext) -> BackupResult:
        if not ctx.file_path:
            self._emit(
                ctx,
                "MESSAGE",
                "⏭ Backup phase: no file_path in context — skipping "
                "(no source artifact to snapshot for this run)",
            )
            return BackupResult(
                backup_reference="",
                backup_type="none",
                original_path=None,
                created_at=utcnow(),
            )

        self._emit(
            ctx,
            "MESSAGE",
            f"💾 Backup phase: snapshotting {ctx.file_path} → .bak-<timestamp> on env2",
        )
        executor = self._executor_for(ctx)
        backup_path, _cmd_result = backup_file(executor, ctx.file_path)
        self._emit(
            ctx,
            "MESSAGE",
            f"✓ Backup created: {backup_path} (rollback anchor persisted to fix_run.backup_reference)",
        )

        return BackupResult(
            backup_reference=backup_path,
            backup_type="file_copy",
            original_path=ctx.file_path,
            created_at=utcnow(),
        )

    # =========================================================================
    # Phase 5 — Execute (edit + plan + apply, per the package's step list)
    # =========================================================================
    def execute(self, ctx: FixContext) -> list[StepResult]:
        executor = self._executor_for(ctx)
        results: list[StepResult] = []

        remediation_steps = ctx.pathway.get("remediation_steps", [])
        if not remediation_steps:
            self._emit(ctx, "ERROR", "No remediation_steps in package pathway")
            return results

        self._emit(
            ctx,
            "MESSAGE",
            f"▶ Execute phase: {len(remediation_steps)} step(s) to run "
            f"(wd={ctx.working_directory}, file={ctx.file_path})",
        )

        for step_num, step_dict in enumerate(remediation_steps, start=1):
            step_text = step_dict.get("step", "") or ""
            action_label = self._action_label(step_text)

            # Announce the step BEFORE parsing — user sees what SA3 emitted
            self._emit(
                ctx,
                "MESSAGE",
                f"→ Step {step_num}/{len(remediation_steps)}: {action_label}",
            )

            # Extract shell blocks from the step text. We deliberately use
            # `_extract_shell_blocks` (whole blocks preserved verbatim) rather
            # than `_extract_commands` (per-line hints). Per-line splitting
            # dropped short lines like the closing `}` of an HCL block, which
            # corrupted `cat >> file << 'EOF' ... EOF` heredocs and produced
            # unclosed configuration blocks. Whole-block extraction preserves
            # heredoc structure exactly as SA3 emitted it.
            blocks = _extract_shell_blocks(step_text)
            if not blocks:
                # SA3 v2.4 shouldn't emit prose-only steps (verifier rejects
                # them). Belt-and-suspenders — record as skipped, but this
                # shouldn't happen in practice.
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⚠ Step {step_num}: no runnable Command:/fenced block found in step text "
                    f"({len(step_text)} chars) — skipping",
                )
                results.append(
                    self._skipped_step(step_num, action_label, "No Command: block found")
                )
                # Skip — don't halt (v2.4 verifier should catch this before us)
                continue

            # Concatenate all blocks with a newline separator. Each block is
            # already a self-contained multi-line shell fragment; a blank line
            # between them is safe (bash treats it as no-op).
            combined = "\n\n".join(blocks)
            self._emit(
                ctx,
                "MESSAGE",
                f"   📝 Extracted {len(blocks)} shell block(s) from step text "
                f"({len(combined)} chars total)",
            )

            # Safety check
            safety = validate_command(combined, ctx.working_directory)
            if not safety.allowed:
                self._emit(
                    ctx,
                    "ERROR",
                    f"🛑 Step {step_num} blocked by safety layer — pattern={safety.matched_pattern!r}, "
                    f"reason: {safety.reason}",
                )
                results.append(self._blocked_step(step_num, action_label, combined, safety.reason))
                return results  # HALT — orchestrator triggers rollback
            self._emit(ctx, "MESSAGE", "   🛡 Safety check passed (no destructive patterns)")

            # Choose a per-step timeout — terraform ops get more headroom
            timeout_s = self._per_step_timeout(combined)
            self._emit(
                ctx,
                "MESSAGE",
                f"   ⏱ Timeout: {timeout_s}s (chosen based on command shape)",
            )

            started = utcnow()
            try:
                cmd_result = executor.run_command(
                    combined,
                    working_directory=ctx.working_directory,
                    timeout_s=timeout_s,
                )
            except (RemoteExecError, CommandTimeoutError) as e:
                finished = utcnow()
                self._emit(
                    ctx,
                    "ERROR",
                    f"✗ Step {step_num} raised {type(e).__name__}: {str(e)[:200]}",
                )
                results.append(
                    StepResult(
                        step_num=step_num,
                        action=action_label,
                        command=combined,
                        stderr=str(e)[:2000],
                        exit_code=-1,
                        duration_ms=int((finished - started).total_seconds() * 1000),
                        status="failed",
                        started_at=started,
                        finished_at=finished,
                        ssm_command_id=None,
                    )
                )
                return results  # HALT

            step_ok = self._step_succeeded(combined, cmd_result.exit_code)
            status = "success" if step_ok else "failed"
            results.append(
                StepResult(
                    step_num=step_num,
                    action=action_label,
                    command=combined,
                    stdout=cmd_result.stdout[:20000],
                    stderr=cmd_result.stderr[:5000],
                    exit_code=cmd_result.exit_code,
                    duration_ms=cmd_result.duration_ms,
                    status=status,
                    started_at=cmd_result.started_at,
                    finished_at=cmd_result.finished_at,
                    ssm_command_id=cmd_result.ssm_command_id,
                )
            )

            if not step_ok:
                self._emit(
                    ctx,
                    "ERROR",
                    f"✗ Step {step_num} exit={cmd_result.exit_code}: {cmd_result.stderr[:200]}",
                )
                return results  # HALT
            else:
                # For `terraform plan -detailed-exitcode` exit=2 means
                # "changes present" (success). Surface this explicitly so
                # the trace reads correctly instead of hiding a non-zero exit.
                extra = (
                    " (exit=2 = changes planned, treated as success)"
                    if cmd_result.exit_code == 2
                    else ""
                )
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"✓ Step {step_num} succeeded ({cmd_result.duration_ms}ms){extra}",
                )

        # If SA3's package did NOT emit an explicit terraform plan step,
        # verify state converged by running one now. This is defensive — it
        # catches the case where the LLM's edit didn't take effect for some
        # reason. Uses the same tools.terraform primitive as everywhere else.
        if not any("terraform plan" in r.command for r in results):
            self._emit(ctx, "MESSAGE", "→ Post-check: running `terraform plan` to verify state")
            plan = terraform_plan(executor, ctx.working_directory or ".", config=self.config)
            check_result = StepResult(
                step_num=len(results) + 1,
                action="Post-check: terraform plan (verify state converged)",
                command="terraform plan -detailed-exitcode",
                stdout=plan.stdout[:20000],
                stderr=plan.stderr[:5000],
                exit_code=plan.exit_code,
                duration_ms=plan.duration_ms,
                status="success" if plan.exit_code in (0, 2) else "failed",
                started_at=plan.command_result.started_at,
                finished_at=plan.command_result.finished_at,
                ssm_command_id=plan.command_result.ssm_command_id,
            )
            results.append(check_result)

        return results

    # =========================================================================
    # Phase 6 — Validate (each validation_test + mandatory re-scan)
    # =========================================================================
    def validate(self, ctx: FixContext) -> list[ValidationResult]:
        executor = self._executor_for(ctx)
        results: list[ValidationResult] = []

        validation_tests = ctx.pathway.get("validation_tests", [])
        if not validation_tests:
            self._emit(ctx, "ERROR", "❌ Validate phase: no validation_tests in package pathway")
            return results

        self._emit(
            ctx,
            "MESSAGE",
            f"🔬 Validate phase: {len(validation_tests)} test(s) queued "
            "(exactly one MUST be a scanner re-scan per SA3 v2.4 hard rule 17)",
        )

        for idx, test in enumerate(validation_tests, start=1):
            test_name = test.get("name", "unnamed")
            method = test.get("method", "manual")
            command = test.get("command", "") or ""
            expected = test.get("expected", "") or ""

            is_rescan = self._looks_like_rescan(command)
            rescan_tag = " ✨ RE-SCAN" if is_rescan else ""

            self._emit(
                ctx,
                "MESSAGE",
                f"→ Test {idx}/{len(validation_tests)}: {test_name}{rescan_tag}",
            )
            self._emit(
                ctx,
                "MESSAGE",
                f"   method={method}, expected≈{self._one_line(expected, 100)!r}",
            )

            if method != "cli":
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"   ⏭ Skipping — method={method!r} not supported in Phase-1 IaC strategy",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command,
                        expected=expected,
                        actual="",
                        passed=False,
                        is_rescan=is_rescan,
                        comparison_note=(
                            f"method={method!r} not supported in Phase-1 IaC strategy "
                            "(cli only). Skipping."
                        ),
                    )
                )
                continue

            safety = validate_command(command, ctx.working_directory)
            if not safety.allowed:
                self._emit(
                    ctx,
                    "ERROR",
                    f"   🛑 Safety blocked test — pattern={safety.matched_pattern!r}: {safety.reason}",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command,
                        expected=expected,
                        actual="",
                        passed=False,
                        is_rescan=is_rescan,
                        comparison_note=f"Safety blocked: {safety.reason}",
                    )
                )
                continue
            try:
                cmd_result = executor.run_command(
                    command,
                    working_directory=ctx.working_directory,
                    timeout_s=self.config.rescan_timeout_s if is_rescan else None,
                )
            except (RemoteExecError, CommandTimeoutError) as e:
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command,
                        expected=expected,
                        actual=str(e)[:500],
                        passed=False,
                        is_rescan=is_rescan,
                        comparison_note=f"Exec error: {type(e).__name__}",
                    )
                )
                continue

            actual = (cmd_result.stdout or "") + (cmd_result.stderr or "")
            passed = self._compare_expected(expected, actual, exit_code=cmd_result.exit_code)

            results.append(
                ValidationResult(
                    test_name=test_name,
                    method=method,
                    command=command,
                    expected=expected,
                    actual=actual[:10000],
                    passed=passed,
                    duration_ms=cmd_result.duration_ms,
                    is_rescan=is_rescan,
                    comparison_note=(
                        "string-contains + exit-zero match"
                        if passed
                        else "expected not found in actual OR non-zero exit"
                    ),
                )
            )

            outcome = "PASSED" if passed else "FAILED"
            self._emit(
                ctx,
                "MESSAGE" if passed else "ERROR",
                f"   {'✓' if passed else '✗'} {test_name}: {outcome} "
                f"(expected≈{self._one_line(expected, 80)!r} vs actual≈{self._one_line(actual, 80)!r})",
            )

        # Summary: how many rescans, how many passed
        rescans = [v for v in results if v.is_rescan]
        passed_ct = sum(1 for v in results if v.passed)
        self._emit(
            ctx,
            "MESSAGE",
            f"🔬 Validate phase complete: {passed_ct}/{len(results)} tests passed "
            f"({len(rescans)} was a scanner re-scan)",
        )
        return results

    # =========================================================================
    # Phase 7 — Rollback (called on any failure OR by promote-to-prod undo)
    # =========================================================================
    def rollback(self, ctx: FixContext) -> list[RollbackResult]:
        results: list[RollbackResult] = []
        if not ctx.backup_reference or not ctx.file_path:
            self._emit(
                ctx,
                "MESSAGE",
                "↶ Rollback phase: no backup_reference or file_path in context — "
                "nothing to restore (backup phase likely didn't complete)",
            )
            return results

        self._emit(
            ctx,
            "MESSAGE",
            f"↶ Rollback phase started — restoring {ctx.file_path} from {ctx.backup_reference}, "
            "then reconciling via terraform apply",
        )

        executor = self._executor_for(ctx)

        # 1. Restore the .bak
        started = utcnow()
        try:
            restore_result = restore_from_backup(executor, ctx.file_path, ctx.backup_reference)
            finished = utcnow()
            results.append(
                RollbackResult(
                    step_num=1,
                    action=f"Restore {ctx.file_path} from {ctx.backup_reference}",
                    command=f"cp {ctx.backup_reference!r} {ctx.file_path!r}",
                    stdout=restore_result.stdout[:2000],
                    stderr=restore_result.stderr[:2000],
                    exit_code=restore_result.exit_code,
                    duration_ms=restore_result.duration_ms,
                    status="success" if restore_result.succeeded else "failed",
                    started_at=restore_result.started_at,
                    finished_at=restore_result.finished_at,
                )
            )
            self._emit(ctx, "MESSAGE", f"↶ Rollback: restored {ctx.file_path}")
        except RemoteExecError as e:
            finished = utcnow()
            results.append(
                RollbackResult(
                    step_num=1,
                    action=f"Restore {ctx.file_path}",
                    command=f"cp {ctx.backup_reference!r} {ctx.file_path!r}",
                    stderr=str(e)[:2000],
                    exit_code=-1,
                    duration_ms=int((finished - started).total_seconds() * 1000),
                    status="failed",
                    started_at=started,
                    finished_at=finished,
                )
            )
            self._emit(ctx, "ERROR", f"Rollback restore failed: {e}")
            return results  # Can't proceed to apply if restore failed

        # 2. Re-apply so live state converges back to pre-fix
        if ctx.working_directory:
            apply_result = terraform_apply(executor, ctx.working_directory, config=self.config)
            results.append(
                RollbackResult(
                    step_num=2,
                    action="terraform apply (reconcile to restored .tf)",
                    command="terraform apply -auto-approve -no-color -input=false",
                    stdout=apply_result.stdout[:20000],
                    stderr=apply_result.stderr[:5000],
                    exit_code=apply_result.exit_code,
                    duration_ms=apply_result.duration_ms,
                    status="success" if apply_result.succeeded else "failed",
                    started_at=apply_result.started_at,
                    finished_at=apply_result.finished_at,
                )
            )
            self._emit(
                ctx,
                "MESSAGE" if apply_result.succeeded else "ERROR",
                f"{'✓' if apply_result.succeeded else '✗'} Rollback: terraform apply "
                f"{'succeeded' if apply_result.succeeded else 'failed'} "
                f"(exit={apply_result.exit_code}, {apply_result.duration_ms}ms)",
            )

        # Rollback summary
        succeeded_ct = sum(1 for r in results if r.status == "success")
        self._emit(
            ctx,
            "MESSAGE",
            f"↶ Rollback phase complete: {succeeded_ct}/{len(results)} steps succeeded. "
            f"{'Env restored to pre-fix state.' if succeeded_ct == len(results) else 'Manual verification recommended.'}",
        )
        return results

    # =========================================================================
    # Helpers
    # =========================================================================
    def _executor_for(self, ctx: FixContext) -> RemoteExecutor:
        """Construct a per-run RemoteExecutor with tracing wired.

        Passes emit_fn + run_id so every SSM call the strategy makes gets
        logged verbatim to agent_trace_events. This is the primary source
        of behind-the-scenes visibility — every command + exit + output
        preview shows up in the UI trace live.
        """
        return RemoteExecutor(
            instance_id=ctx.target_instance_id,
            region=ctx.aws_region,
            config=self.config,
            emit_fn=self.emit_fn,
            run_id=ctx.agent_run_id,
        )

    def _emit(self, ctx: FixContext, event_type: str, message: str) -> None:
        try:
            self.emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                event_type,
                message,
            )
        except Exception:  # noqa: BLE001, S110 — trace best-effort
            pass

    @staticmethod
    def _action_label(step_text: str) -> str:
        """First non-blank line of the step, capped."""
        for line in step_text.splitlines():
            line = line.strip()
            if line:
                return line[:150]
        return "(no action line)"

    @staticmethod
    def _one_line(text: str, cap: int = 100) -> str:
        """Collapse whitespace + newlines for readable one-line trace previews."""
        if not text:
            return ""
        collapsed = " ".join(str(text).split())
        return collapsed[:cap] + ("…" if len(collapsed) > cap else "")

    @staticmethod
    def _step_succeeded(command: str, exit_code: int) -> bool:
        """Semantic success check that understands command-specific exit codes.

        `terraform plan -detailed-exitcode` uses a three-state exit code:
          0 → no changes needed (success)
          1 → error (failure)
          2 → changes present (success — this is the *expected* outcome
              after an edit step; treating it as failure aborts every fix
              that actually did something)

        Everything else follows the standard shell convention: 0 = success.
        """
        cmd_l = command.lower()
        if "terraform plan" in cmd_l and "-detailed-exitcode" in cmd_l:
            return exit_code in (0, 2)
        return exit_code == 0

    def _per_step_timeout(self, command: str) -> int:
        """Return the appropriate SSM timeout for the command shape."""
        if "terraform apply" in command:
            return self.config.terraform_apply_timeout_s
        if "terraform plan" in command:
            return self.config.terraform_plan_timeout_s
        if "terraform init" in command:
            return self.config.terraform_init_timeout_s
        if any(v in command for v in _SCANNER_CLI_VERBS):
            return self.config.rescan_timeout_s
        return self.config.ssm_command_timeout_s

    @staticmethod
    def _looks_like_rescan(command: str) -> bool:
        """Heuristic: does the validation command invoke a scanner CLI?"""
        # First-token check protects against strings that only mention the
        # scanner name in a comment or path (e.g. `cat /opt/checkov-...`).
        first_tokens = command.split(maxsplit=2)
        candidate = first_tokens[0] if first_tokens else ""
        # Strip any leading path (/usr/local/bin/checkov → checkov)
        candidate = candidate.rsplit("/", 1)[-1]
        return candidate in _SCANNER_CLI_VERBS

    @staticmethod
    def _compare_expected(expected: str, actual: str, *, exit_code: int) -> bool:
        """MVP comparison: expected string appears in actual output AND exit was zero.

        Nikhil's design calls for LLM-based semantic comparison in v1.4+.
        For MVP we string-contains match — works for the "expected: 'BlockPublicAcls: true'"
        + "expected: '0 failed checks'" shapes SA3 v2.4 emits.
        """
        if exit_code != 0:
            return False
        if not expected:
            # If the package didn't declare an expected string, just trust exit code
            return True
        return expected.strip() in actual

    @staticmethod
    def _skipped_step(step_num: int, action: str, reason: str) -> StepResult:
        ts = utcnow()
        return StepResult(
            step_num=step_num,
            action=action,
            command="",
            status="skipped",
            started_at=ts,
            finished_at=ts,
            adaptation_note=reason,
        )

    @staticmethod
    def _blocked_step(step_num: int, action: str, command: str, reason: str) -> StepResult:
        ts = utcnow()
        return StepResult(
            step_num=step_num,
            action=action,
            command=command,
            status="safety_blocked",
            safety_reason=reason,
            started_at=ts,
            finished_at=ts,
        )
