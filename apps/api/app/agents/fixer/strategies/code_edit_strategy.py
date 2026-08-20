"""CodeEditStrategy — concrete strategy for SAST/code-level findings.

Implements the source-code remediation flow for findings from Semgrep,
Bandit, SonarQube, gosec, and other SAST scanners:

  pre_flight → backup → execute (edit source) → validate (syntax + re-scan)
                                             ↘ rollback (restore .bak)

Design principles (same as IaCStrategy):
  1. GENERIC EXECUTION — no hardcoding of rule IDs, languages, or CWE types.
     All vulnerability-specific knowledge lives in the package that SA3 produced.
  2. STRICT COMMAND PROVENANCE — every command that runs on env2 was emitted
     BY SA3 into the package's remediation_steps. CodeEditStrategy never
     invents fix commands (except the mechanical backup + restore).
  3. SAFETY BEFORE DISPATCH — every command passes safety.validate_command.
  4. TRACE-ALL — one trace event per phase + per step for UI live-view.

Key difference from IaCStrategy:
  - No terraform plan/apply cycle (source code doesn't need infra reconciliation)
  - No vulnerable-pattern guard (re-scan with the SAST scanner IS the guard)
  - Simpler rollback (just restore the .bak, no terraform apply needed)
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
from .base import BaseFixStrategy


# Scanner CLI markers — used to detect which validation_test is the re-scan.
_SCANNER_CLI_VERBS: tuple[str, ...] = (
    "semgrep",
    "bandit",
    "sonar-scanner",
    "sonarqube",
    "gosec",
    "eslint",
    "spotbugs",
    "checkov",
    "trivy",
)


class CodeEditStrategy(BaseFixStrategy):
    """Strategy for SAST/code-level findings (Semgrep, Bandit, SonarQube, etc.).

    Executes source-code edits from the package's remediation_steps, validates
    with syntax checks and scanner re-scan. No infrastructure reconciliation
    layer — the file edit IS the fix.
    """

    name = "Code Edit (SAST)"
    strategy_key = "code_edit"

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

        # 2. Target file exists
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
                    f"instance {ctx.target_instance_id!r}. Cannot proceed with source edit."
                )
                self._emit(ctx, "ERROR", f"✗ Pre-flight: {reason}")
                return PreFlightResult(ready=False, checks=checks, blocking_reason=reason)
            self._emit(ctx, "MESSAGE", f"✓ Pre-flight: {ctx.file_path} present")
        else:
            reason = "No file_path in context — CodeEditStrategy requires a target source file."
            self._emit(ctx, "ERROR", f"✗ Pre-flight: {reason}")
            return PreFlightResult(ready=False, checks=checks, blocking_reason=reason)

        # 3. Scanner available for re-scan (best-effort check — non-blocking)
        source = (ctx.issue.get("source") or "").lower()
        scanner_cmd = self._detect_scanner_binary(source)
        if scanner_cmd:
            probe = executor.run_command(f"which {scanner_cmd}")
            scanner_available = probe.exit_code == 0
            checks.append(
                {
                    "check": "scanner_available",
                    "passed": scanner_available,
                    "scanner": scanner_cmd,
                }
            )
            if scanner_available:
                self._emit(ctx, "MESSAGE", f"✓ Pre-flight: {scanner_cmd} binary present")
            else:
                # Non-blocking — the re-scan validation will fail, but we let
                # the orchestrator handle that via the validation phase.
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⚠ Pre-flight: {scanner_cmd} not found on PATH (re-scan validation may fail)",
                )

        return PreFlightResult(ready=True, checks=checks)

    # =========================================================================
    # Phase 4 — Backup
    # =========================================================================
    def backup(self, ctx: FixContext) -> BackupResult:
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
            f"✓ Backup created: {backup_path}",
        )

        return BackupResult(
            backup_reference=backup_path,
            backup_type="file_copy",
            original_path=ctx.file_path,
            created_at=utcnow(),
        )

    # =========================================================================
    # Phase 5 — Execute (edit the source file per the package's step list)
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
            f"▶ Execute phase: {len(remediation_steps)} step(s) to run (file={ctx.file_path})",
        )

        for step_num, step_dict in enumerate(remediation_steps, start=1):
            step_text = step_dict.get("step", "") or ""
            action_label = self._action_label(step_text)

            self._emit(
                ctx,
                "MESSAGE",
                f"→ Step {step_num}/{len(remediation_steps)}: {action_label}",
            )

            # Extract shell blocks from the step text
            blocks = _extract_shell_blocks(step_text)
            if not blocks:
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⚠ Step {step_num}: no runnable Command: block found — skipping",
                )
                results.append(
                    self._skipped_step(step_num, action_label, "No Command: block found")
                )
                continue

            combined = "\n\n".join(blocks)
            self._emit(
                ctx,
                "MESSAGE",
                f"   📝 Extracted {len(blocks)} shell block(s) ({len(combined)} chars)",
            )

            # Safety check
            safety = validate_command(combined, ctx.working_directory)
            if not safety.allowed:
                self._emit(
                    ctx,
                    "ERROR",
                    f"🛑 Step {step_num} blocked by safety — "
                    f"pattern={safety.matched_pattern!r}: {safety.reason}",
                )
                results.append(self._blocked_step(step_num, action_label, combined, safety.reason))
                return results  # HALT — orchestrator triggers rollback

            # Determine timeout
            timeout_s = self._per_step_timeout(combined)

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

            step_ok = cmd_result.exit_code == 0
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
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"✓ Step {step_num} succeeded ({cmd_result.duration_ms}ms)",
                )

        return results

    # =========================================================================
    # Phase 6 — Validate (syntax check + validation_tests + mandatory re-scan)
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
            f"🔬 Validate phase: {len(validation_tests)} test(s) queued",
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

            if method != "cli":
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"   ⏭ Skipping — method={method!r} not supported in CodeEditStrategy",
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
                        comparison_note=f"method={method!r} not supported (cli only)",
                    )
                )
                continue

            # Safety check
            safety = validate_command(command, ctx.working_directory)
            if not safety.allowed:
                self._emit(
                    ctx,
                    "ERROR",
                    f"   🛑 Safety blocked test — {safety.reason}",
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

            # Execute the validation command
            timeout_s = (
                self.config.rescan_timeout_s if is_rescan else self.config.ssm_command_timeout_s
            )
            try:
                cmd_result = executor.run_command(
                    command,
                    working_directory=ctx.working_directory,
                    timeout_s=timeout_s,
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
                f"   {'✓' if passed else '✗'} {test_name}: {outcome}",
            )

        # Summary
        rescans = [v for v in results if v.is_rescan]
        passed_ct = sum(1 for v in results if v.passed)
        self._emit(
            ctx,
            "MESSAGE",
            f"🔬 Validate phase complete: {passed_ct}/{len(results)} tests passed "
            f"({len(rescans)} scanner re-scan(s))",
        )
        return results

    # =========================================================================
    # Phase 7 — Rollback (restore .bak file — no infra reconciliation needed)
    # =========================================================================
    def rollback(self, ctx: FixContext) -> list[RollbackResult]:
        results: list[RollbackResult] = []
        if not ctx.backup_reference or not ctx.file_path:
            self._emit(
                ctx,
                "MESSAGE",
                "↶ Rollback phase: no backup_reference or file_path — nothing to restore",
            )
            return results

        self._emit(
            ctx,
            "MESSAGE",
            f"↶ Rollback phase: restoring {ctx.file_path} from {ctx.backup_reference}",
        )

        executor = self._executor_for(ctx)

        started = utcnow()
        try:
            restore_result = restore_from_backup(executor, ctx.file_path, ctx.backup_reference)
            results.append(
                RollbackResult(
                    step_num=1,
                    action=f"Restore {ctx.file_path} from backup",
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
            if restore_result.succeeded:
                self._emit(ctx, "MESSAGE", f"✓ Rollback: restored {ctx.file_path}")
            else:
                self._emit(
                    ctx, "ERROR", f"✗ Rollback: restore failed — {restore_result.stderr[:200]}"
                )
        except RemoteExecError as e:
            finished = utcnow()
            results.append(
                RollbackResult(
                    step_num=1,
                    action=f"Restore {ctx.file_path} from backup",
                    command=f"cp {ctx.backup_reference!r} {ctx.file_path!r}",
                    stderr=str(e)[:2000],
                    exit_code=-1,
                    duration_ms=int((finished - started).total_seconds() * 1000),
                    status="failed",
                    started_at=started,
                    finished_at=finished,
                )
            )
            self._emit(ctx, "ERROR", f"✗ Rollback failed: {e}")

        succeeded_ct = sum(1 for r in results if r.status == "success")
        self._emit(
            ctx,
            "MESSAGE",
            f"↶ Rollback complete: {succeeded_ct}/{len(results)} step(s) succeeded. "
            f"{'Source file restored.' if succeeded_ct == len(results) else 'Manual verification recommended.'}",
        )
        return results

    # =========================================================================
    # Helpers
    # =========================================================================
    def _executor_for(self, ctx: FixContext) -> RemoteExecutor:
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
        except Exception:  # noqa: BLE001, S110
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
        """Collapse whitespace for one-line trace previews."""
        if not text:
            return ""
        collapsed = " ".join(str(text).split())
        return collapsed[:cap] + ("…" if len(collapsed) > cap else "")

    def _per_step_timeout(self, command: str) -> int:
        """Return appropriate timeout for the command shape."""
        if any(v in command for v in _SCANNER_CLI_VERBS):
            return self.config.rescan_timeout_s
        return self.config.ssm_command_timeout_s

    @staticmethod
    def _looks_like_rescan(command: str) -> bool:
        """Heuristic: does the validation command invoke a scanner CLI?"""
        first_tokens = command.split(maxsplit=2)
        candidate = first_tokens[0] if first_tokens else ""
        candidate = candidate.rsplit("/", 1)[-1]
        return candidate in _SCANNER_CLI_VERBS

    @staticmethod
    def _compare_expected(expected: str, actual: str, *, exit_code: int) -> bool:
        """MVP comparison: expected string in actual output AND exit was zero.

        For SAST re-scans, the typical pattern is:
          command: semgrep ... | grep -c '<rule_id>' || true
          expected: "0"
        So we check that "0" appears in the output and exit was 0.
        """
        if exit_code != 0:
            return False
        if not expected:
            return True
        return expected.strip() in actual

    @staticmethod
    def _detect_scanner_binary(source: str) -> str | None:
        """Map source name to the scanner binary for pre-flight probing."""
        if "semgrep" in source:
            return "semgrep"
        if "bandit" in source:
            return "bandit"
        if "sonarqube" in source or "sonar" in source:
            return "sonar-scanner"
        if "gosec" in source:
            return "gosec"
        return None

    @staticmethod
    def _skipped_step(step_num: int, action: str, reason: str) -> StepResult:
        now = utcnow()
        return StepResult(
            step_num=step_num,
            action=action,
            command="",
            status="skipped",
            started_at=now,
            finished_at=now,
            adaptation_note=reason,
        )

    @staticmethod
    def _blocked_step(step_num: int, action: str, command: str, reason: str) -> StepResult:
        now = utcnow()
        return StepResult(
            step_num=step_num,
            action=action,
            command=command,
            status="safety_blocked",
            started_at=now,
            finished_at=now,
            safety_reason=reason,
        )
