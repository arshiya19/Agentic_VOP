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
from .base import CLOUD_DEPLOY_RE, CLOUD_RUNTIME_LOOKUP_RE, BaseFixStrategy


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

        # Isolate-failures detection: in either of these cases, individual
        # EDIT_FILE / VERIFY_ABSENT failures use status "skipped" and `continue`
        # instead of halting the whole package. Non-structured steps (backup,
        # py_compile, etc.) still halt-on-fail — they're prerequisites, not
        # supplementary checks.
        #
        #  a) Batch mode — >1 #EDIT_FILE marker in this pathway (per-file batch
        #     covering multiple findings) → don't let one bad edit undo the
        #     good ones.
        #  b) Planner batch marker — `__batch_covered_ids__:...` in
        #     considerations means the planner batched N findings even if
        #     SA-3 only emitted 1 edit; still treat as isolated.
        #  c) Scanner re-scan queued — the pathway will run a scanner re-scan
        #     in the Validate phase, which is the AUTHORITATIVE judge of
        #     whether the vulnerability is gone. Supplementary sub-step checks
        #     (substring VERIFY_ABSENT, EDIT_FILE old_text-not-found) should
        #     not halt the run before the authority has spoken; if the scanner
        #     re-scan later fails, orchestrator will still rollback.
        _edit_file_marker_count = sum(
            1 for s in remediation_steps if "#EDIT_FILE" in (s.get("step", "") or "")
        )
        _batch_covered_marker = any(
            (c or "").startswith("__batch_covered_ids__:")
            for c in (ctx.pathway.get("considerations") or [])
        )
        _scanner_rescan_queued = any(
            self._looks_like_rescan(t.get("command", "") or "")
            for t in (ctx.pathway.get("validation_tests") or [])
        )
        _batch_mode = _edit_file_marker_count > 1 or _batch_covered_marker or _scanner_rescan_queued
        if _batch_mode:
            if _edit_file_marker_count > 1:
                _reason = (
                    f"🧩 Isolate-failures mode: {_edit_file_marker_count} structured edits in this package — "
                    f"individual failures will be isolated (one bad edit won't undo the good ones)"
                )
            elif _batch_covered_marker:
                _reason = (
                    "🧩 Isolate-failures mode: planner batched multiple findings into this package — "
                    "sub-step failures won't halt the run before the scanner re-scan judges"
                )
            else:
                _reason = (
                    "🧩 Isolate-failures mode: scanner re-scan queued as authoritative judge — "
                    "supplementary sub-check failures won't halt the run"
                )
            self._emit(ctx, "MESSAGE", _reason)

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

            # Structured-op branches: if the step contains a #EDIT_FILE or
            # #VERIFY_ABSENT marker, parse + dispatch to the corresponding
            # executor (base64-encoded SSM roundtrip, zero shell parsing of
            # the payload). Falls back to shell extraction otherwise, OR when
            # SA3_DISABLE_EDIT_FILE=true (guard covers both structured tools —
            # they share the same tolerance semantic).
            import os as _os  # noqa: PLC0415

            _edit_file_disabled = _os.getenv("SA3_DISABLE_EDIT_FILE", "").lower() in (
                "1",
                "true",
                "yes",
            )
            from ..tools.edit_file import (  # noqa: PLC0415
                is_edit_file_step,
                parse_edit_spec,
                build_ssm_command,
                summarize_spec,
                sanity_check_version_edit,
                is_verify_absent_step,
                parse_verify_absent_spec,
                build_verify_absent_ssm_command,
                summarize_verify_absent,
            )

            # ---- #VERIFY_ABSENT branch (evaluated first — cheap check) ----
            if not _edit_file_disabled and is_verify_absent_step(step_text):
                try:
                    vspec = parse_verify_absent_spec(step_text)
                except ValueError as e:
                    self._emit(
                        ctx,
                        "ERROR",
                        f"🛑 Step {step_num} VERIFY_ABSENT spec invalid: {e} — skipping",
                    )
                    results.append(
                        self._skipped_step(
                            step_num, action_label, f"invalid VERIFY_ABSENT spec: {e}"
                        )
                    )
                    if _batch_mode:
                        continue  # isolate — don't halt sibling edits
                    return results
                verify_cmd = build_verify_absent_ssm_command(vspec)
                self._emit(
                    ctx, "MESSAGE", f"   🔍 Structured verify: {summarize_verify_absent(vspec)}"
                )
                started = utcnow()
                try:
                    cmd_result = executor.run_command(
                        verify_cmd, working_directory=None, timeout_s=60
                    )
                except (RemoteExecError, CommandTimeoutError) as e:
                    finished = utcnow()
                    _fail_status = "skipped" if _batch_mode else "failed"
                    self._emit(
                        ctx,
                        "ERROR" if not _batch_mode else "MESSAGE",
                        f"{'⏭' if _batch_mode else '✗'} Step {step_num} VERIFY_ABSENT raised {type(e).__name__}: {str(e)[:200]}"
                        + (" — isolated (batch mode)" if _batch_mode else ""),
                    )
                    results.append(
                        StepResult(
                            step_num=step_num,
                            action=action_label,
                            command=verify_cmd,
                            stderr=str(e)[:2000],
                            exit_code=-1,
                            duration_ms=int((finished - started).total_seconds() * 1000),
                            status=_fail_status,
                            started_at=started,
                            finished_at=finished,
                            ssm_command_id=None,
                        )
                    )
                    if _batch_mode:
                        continue
                    return results
                finished = utcnow()
                step_ok = cmd_result.exit_code == 0
                # In batch mode, a "failed" verify becomes "skipped" so the
                # orchestrator doesn't halt/rollback the sibling edits.
                if step_ok:
                    status = "success"
                elif _batch_mode:
                    status = "skipped"
                else:
                    status = "failed"
                results.append(
                    StepResult(
                        step_num=step_num,
                        action=action_label,
                        command=verify_cmd,
                        stdout=cmd_result.stdout[:2000],
                        stderr=cmd_result.stderr[:2000],
                        exit_code=cmd_result.exit_code,
                        duration_ms=int((finished - started).total_seconds() * 1000),
                        status=status,
                        started_at=started,
                        finished_at=finished,
                        ssm_command_id=cmd_result.ssm_command_id,
                    )
                )
                if step_ok:
                    self._emit(
                        ctx, "MESSAGE", f"✓ Step {step_num} VERIFY_ABSENT passed (pattern gone)"
                    )
                    continue
                # Failure branch
                if _batch_mode:
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"⏭ Step {step_num} VERIFY_ABSENT failed (pattern still present) — "
                        f"isolated in batch mode, sibling edits keep going",
                    )
                    continue
                self._emit(
                    ctx,
                    "ERROR",
                    f"✗ Step {step_num} VERIFY_ABSENT exit={cmd_result.exit_code}: {cmd_result.stderr[:300]}",
                )
                return results
            if not _edit_file_disabled and is_edit_file_step(step_text):
                try:
                    spec = parse_edit_spec(step_text)
                except ValueError as e:
                    self._emit(
                        ctx,
                        "ERROR",
                        f"🛑 Step {step_num} EDIT_FILE spec invalid: {e} — skipping",
                    )
                    results.append(
                        self._skipped_step(step_num, action_label, f"invalid EDIT_FILE spec: {e}")
                    )
                    if _batch_mode:
                        continue
                    return results  # HALT — orchestrator triggers rollback

                # Sanity-check version-pin edits BEFORE the SSM round-trip.
                # Catches LLM hallucination classes (same-version no-op,
                # downgrade, package-name swap) generically — any scanner
                # whose fix is a `pkg==version` bump benefits. Non-version
                # edits fall through with None. Always non-fatal — flagged
                # edits become skipped steps, sibling edits keep going.
                _sanity_skip = sanity_check_version_edit(spec)
                if _sanity_skip:
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"⏭ Step {step_num} EDIT_FILE skipped by pre-dispatch sanity: {_sanity_skip}",
                    )
                    results.append(self._skipped_step(step_num, action_label, _sanity_skip))
                    continue
                edit_cmd = build_ssm_command(spec)
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"   ✎ Structured edit: {summarize_spec(spec)}",
                )
                started = utcnow()
                try:
                    cmd_result = executor.run_command(
                        edit_cmd,
                        working_directory=None,  # spec contains absolute path
                        timeout_s=60,
                    )
                except (RemoteExecError, CommandTimeoutError) as e:
                    finished = utcnow()
                    _fail_status = "skipped" if _batch_mode else "failed"
                    self._emit(
                        ctx,
                        "ERROR" if not _batch_mode else "MESSAGE",
                        f"{'⏭' if _batch_mode else '✗'} Step {step_num} EDIT_FILE raised {type(e).__name__}: {str(e)[:200]}"
                        + (" — isolated (batch mode)" if _batch_mode else ""),
                    )
                    results.append(
                        StepResult(
                            step_num=step_num,
                            action=action_label,
                            command=edit_cmd,
                            stderr=str(e)[:2000],
                            exit_code=-1,
                            duration_ms=int((finished - started).total_seconds() * 1000),
                            status=_fail_status,
                            started_at=started,
                            finished_at=finished,
                            ssm_command_id=None,
                        )
                    )
                    if _batch_mode:
                        continue
                    return results  # HALT
                step_ok = cmd_result.exit_code == 0
                # In batch mode, a "failed" edit becomes "skipped" — the file
                # is UNCHANGED (edit_file refuses to write on any error), so
                # sibling edits process against the same file view SA-3 saw.
                if step_ok:
                    status = "success"
                elif _batch_mode:
                    status = "skipped"
                else:
                    status = "failed"
                finished = utcnow()
                results.append(
                    StepResult(
                        step_num=step_num,
                        action=action_label,
                        command=edit_cmd,
                        stdout=cmd_result.stdout[:2000],
                        stderr=cmd_result.stderr[:2000],
                        exit_code=cmd_result.exit_code,
                        duration_ms=int((finished - started).total_seconds() * 1000),
                        status=status,
                        started_at=started,
                        finished_at=finished,
                        ssm_command_id=cmd_result.ssm_command_id,
                    )
                )
                if step_ok:
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"✓ Step {step_num} EDIT_FILE applied (exit=0, {int((finished - started).total_seconds() * 1000)}ms)",
                    )
                    continue  # next step
                # Failure path
                if _batch_mode:
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"⏭ Step {step_num} EDIT_FILE exit={cmd_result.exit_code}: "
                        f"{cmd_result.stderr[:200]} — isolated in batch mode, "
                        f"sibling edits keep going",
                    )
                    continue
                self._emit(
                    ctx,
                    "ERROR",
                    f"✗ Step {step_num} EDIT_FILE exit={cmd_result.exit_code}: {cmd_result.stderr[:300]}",
                )
                return results  # HALT

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

            # Strategy policy hook — subclasses may skip runtime-mutating or
            # env-dependent commands that a file-based scanner doesn't need.
            # Returns None to run, or a reason string to skip.
            skip_reason = self._should_skip_shell_step(combined, ctx)
            if skip_reason:
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⏭ Step {step_num} skipped by strategy policy: {skip_reason}",
                )
                results.append(self._skipped_step(step_num, action_label, skip_reason))
                continue

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

            # Strategy policy hook — same policy as execute(). Runtime-lookup
            # tests (`aws lambda invoke`, `aws secretsmanager get-secret-value`)
            # can't verify a static remediation and require prod-tier IAM the
            # sandbox doesn't have. Mark as passed=True with a clear note so
            # they neither block the run nor pretend to have verified anything.
            skip_reason = self._should_skip_shell_step(command, ctx)
            if skip_reason:
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"   ⏭ Test {idx} skipped by strategy policy: {skip_reason[:150]}",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command,
                        expected=expected,
                        actual="",
                        passed=True,
                        is_rescan=is_rescan,
                        comparison_note=f"SKIPPED by strategy policy — not executed: {skip_reason}",
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
            if is_rescan:
                passed, note = self._evaluate_rescan_result(
                    stdout=cmd_result.stdout or "",
                    stderr=cmd_result.stderr or "",
                    exit_code=cmd_result.exit_code,
                )
            else:
                passed = self._compare_expected(expected, actual, exit_code=cmd_result.exit_code)
                note = (
                    "string-contains + exit-zero match"
                    if passed
                    else "expected not found in actual OR non-zero exit"
                )

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
                    comparison_note=note,
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
    # Strategy policy hook (subclasses override)
    # =========================================================================
    def _should_skip_shell_step(self, command: str, ctx: FixContext) -> str | None:  # noqa: ARG002
        """Policy hook — return a reason string to skip this shell step, or None to run it.

        CodeEditStrategy (and every subclass — DependencyStrategy inherits)
        enforces the STATIC REMEDIATION contract: the strategy edits source
        files and re-runs the scanner. It does NOT deploy the change to a
        runtime or fetch runtime state. Those are downstream CI/CD concerns.

        This deterministic guard makes the guarantee independent of whatever
        the LLM plan happens to include — the plan may still emit deploy
        commands, but they never execute.

        The scanner re-scan step (semgrep/checkov/trivy/etc.) is exempted
        because it IS the authoritative validator of a static fix.
        """
        # Never skip the re-scan — it's how we know the fix worked.
        if self._looks_like_rescan(command):
            return None

        if CLOUD_DEPLOY_RE.search(command):
            return (
                "static remediation is file-only — cloud-deploy commands "
                "(aws lambda update-*, terraform apply, kubectl apply, "
                "helm install, docker push, serverless deploy, ...) belong "
                "to CI/CD, not the remediation service. The scanner re-scan "
                "reads the FILE, so file edits alone satisfy it."
            )
        if CLOUD_RUNTIME_LOOKUP_RE.search(command):
            return (
                "static remediation is file-only — runtime-lookup commands "
                "(aws secretsmanager get-secret-value, aws lambda invoke, "
                "aws ssm get-parameter, ...) aren't needed. The scanner "
                "reads source code, not runtime values."
            )
        return None

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
    def _evaluate_rescan_result(*, stdout: str, stderr: str, exit_code: int) -> tuple[bool, str]:
        """Judge a scanner re-scan by scanner semantics, not by the LLM's `expected` string.

        Every mainstream SAST/SCA scanner shares a common exit-code contract:
          exit=0 → no findings (fix landed ✓)
          exit=1 → findings present (fix didn't land ✗)
          exit=2+ → scanner error (fix undecidable ✗)

        This holds for semgrep, bandit, gosec, checkov, trivy (default),
        sonar-scanner, eslint. The LLM's `expected` field ("no results",
        "0 findings", etc.) is IGNORED because it's guessed text that never
        matches raw scanner JSON output.

        When output is JSON, we double-check: a well-formed `"results":[]`
        (Semgrep/Checkov/Bandit) or `"Results":[{"Vulnerabilities": null}]`
        (Trivy) definitively says PASSED regardless of exit code — some
        scanners return non-zero even on success depending on flags.

        Returns (passed, comparison_note) so the trace shows why.
        """
        import json as _json  # noqa: PLC0415

        # First check the JSON body — most authoritative signal.
        # Some scanners emit an ASCII banner or progress bar to stdout
        # before/around the JSON payload (e.g. Semgrep without --quiet), so
        # we scan for a balanced-brace object rather than requiring the
        # first character to be `{`. We look at stdout and stderr both.
        def _extract_json_candidates(text: str) -> list[str]:
            candidates: list[str] = []
            for start in range(len(text)):
                if text[start] not in "{[":
                    continue
                open_ch = text[start]
                close_ch = "}" if open_ch == "{" else "]"
                depth = 0
                for i in range(start, len(text)):
                    if text[i] == open_ch:
                        depth += 1
                    elif text[i] == close_ch:
                        depth -= 1
                        if depth == 0:
                            candidates.append(text[start : i + 1])
                            break
                if candidates:
                    break  # only the first top-level object matters here
            return candidates

        for text in (stdout, stderr):
            text = text or ""
            for candidate in _extract_json_candidates(text):
                try:
                    data = _json.loads(candidate)
                except (ValueError, TypeError):
                    continue

                # Semgrep / Bandit / Checkov shape: top-level "results" list
                results = data.get("results") if isinstance(data, dict) else None
                if isinstance(results, list):
                    if not results:
                        return True, "scanner JSON reports empty results — no findings"
                    return (
                        False,
                        f"scanner JSON reports {len(results)} finding(s) — fix did not land",
                    )

                # Trivy shape: top-level "Results" list, each with "Vulnerabilities"
                results = data.get("Results") if isinstance(data, dict) else None
                if isinstance(results, list):
                    total_vulns = 0
                    for r in results:
                        if not isinstance(r, dict):
                            continue
                        total_vulns += len(r.get("Vulnerabilities") or [])
                        total_vulns += len(r.get("Misconfigurations") or [])
                    if total_vulns == 0:
                        return True, "scanner JSON (Trivy shape) reports no vulnerabilities"
                    return False, f"scanner JSON (Trivy shape) reports {total_vulns} finding(s)"

        # No parseable JSON — fall back to exit-code semantics
        if exit_code == 0:
            return True, "scanner exited 0 — no findings"
        if exit_code == 1:
            return False, f"scanner exited {exit_code} — findings present"
        return False, (
            f"scanner exited {exit_code} — likely error, not a fix verdict "
            f"(stderr: {(stderr or '')[:200]})"
        )

    @staticmethod
    def _detect_scanner_binary(source: str) -> str | None:
        """Map source name to the scanner binary for pre-flight probing."""
        if "semgrep" in source or "serverless" in source:
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
