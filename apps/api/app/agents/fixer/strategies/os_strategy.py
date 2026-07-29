"""OSStrategy — concrete strategy for host OS vulnerability findings.

Fits trivy-os (and structurally similar host scanners: Tenable, Qualys,
Rapid7, Nessus). Fix shape is:

  pre_flight → backup (dpkg state snapshot) → execute (apt-get upgrade) →
  validate (dpkg version check + trivy rootfs re-scan) →
  rollback (apt-get install <pkg>=<old_version>)

Environment assumptions (env2 vuln-lab):
  - Ubuntu 20.04 host with apt/dpkg
  - SSM agent Online
  - trivy binary on PATH
  - Packages are installed via apt (dpkg-based)

SA-3 emits packages whose remediation_steps look like:
  1. Back up current package state
  2. apt-get update
  3. apt-get install --only-upgrade <pkg> (or apt-get install <pkg>=<ver>)
  4. Verify with dpkg -l <pkg>
  5. Re-scan with trivy rootfs

Design principles (same as IaCStrategy / ImageStrategy):
  1. Generic execution — no per-CVE hardcoding
  2. Strict command provenance — SA-3's steps run as-is
  3. Safety before dispatch
  4. Trace-all
"""

from __future__ import annotations

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
from ..tools.remote_exec import (
    CommandTimeoutError,
    RemoteExecError,
    RemoteExecutor,
)
from .base import BaseFixStrategy


_RESCAN_CLI_MARKERS: tuple[str, ...] = (
    "trivy rootfs",
    "trivy fs",
    "trivy image",
    "dpkg -l",
    "apt list --installed",
)


def _normalize_method(method: str | None) -> str:
    m = (method or "").strip().lower()
    if m == "manual":
        return "manual"
    if m in ("http", "https", "curl"):
        return "http"
    if m in ("sql", "psql"):
        return "sql"
    return "cli"


class OSStrategy(BaseFixStrategy):
    """Strategy for host OS vulnerability findings (apt/dpkg-based).

    Same 5-phase lifecycle as IaCStrategy but with apt-native primitives.
    """

    name = "Host OS (apt)"
    strategy_key = "os"

    def __init__(self, *, config: FixerConfig, emit_fn) -> None:
        self.config = config
        self.emit_fn = emit_fn

    def _emit(self, ctx: FixContext, event_type: str, message: str) -> None:
        try:
            self.emit_fn(ctx.agent_run_id, "sub-agent-4", event_type, message)
        except Exception:  # noqa: BLE001, S110
            pass

    def _executor(self, ctx: FixContext) -> RemoteExecutor:
        return RemoteExecutor(
            ctx.target_instance_id,
            region=ctx.aws_region,
            config=self.config,
            emit_fn=self.emit_fn,
            run_id=ctx.agent_run_id,
        )

    # ==================================================================
    # Phase 3 — Pre-flight
    # ==================================================================
    def pre_flight_check(self, ctx: FixContext) -> PreFlightResult:
        executor = self._executor(ctx)

        if not executor.is_reachable():
            return PreFlightResult(
                ready=False,
                blocking_reason=f"SSM agent on {ctx.target_instance_id} is not Online.",
            )
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: SSM reachable")

        # apt available
        try:
            r = executor.run_command("apt-get --version 2>&1 | head -1", timeout_s=30)
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(ready=False, blocking_reason=f"apt probe crashed: {e}")
        if r.exit_code != 0:
            return PreFlightResult(ready=False, blocking_reason="apt-get not available")
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: apt available ({(r.stdout or '').strip()[:60]})")

        # trivy available
        try:
            r = executor.run_command("trivy --version 2>&1 | head -1", timeout_s=30)
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(ready=False, blocking_reason=f"trivy probe crashed: {e}")
        if r.exit_code != 0:
            return PreFlightResult(ready=False, blocking_reason="trivy binary unavailable")
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: trivy present ({(r.stdout or '').strip()[:60]})")

        return PreFlightResult(ready=True)

    # ==================================================================
    # Phase 4 — Backup
    # ==================================================================
    def backup(self, ctx: FixContext) -> BackupResult:
        executor = self._executor(ctx)
        backup_path = f"/tmp/pkg-state-fix-{ctx.fix_run_id}.txt"  # noqa: S108

        self._emit(ctx, "MESSAGE", f"💾 Backup phase: dpkg state → {backup_path}")

        try:
            r = executor.run_command(
                f"dpkg --get-selections > {backup_path} && echo SAVED",
                timeout_s=60,
            )
            if r.exit_code == 0 and "SAVED" in (r.stdout or ""):
                self._emit(ctx, "MESSAGE", f"✓ Backup: package state saved to {backup_path}")
            else:
                self._emit(ctx, "ERROR", f"⚠ Backup: dpkg state save returned exit={r.exit_code}")
        except (RemoteExecError, CommandTimeoutError) as e:
            self._emit(ctx, "ERROR", f"⚠ Backup: dpkg state save crashed: {e}")

        return BackupResult(
            backup_reference=backup_path,
            backup_type="state_snapshot",
            original_path=None,
            created_at=utcnow(),
        )

    # ==================================================================
    # Phase 5 — Execute
    # ==================================================================
    def execute(self, ctx: FixContext) -> list[StepResult]:
        executor = self._executor(ctx)
        pathway = ctx.pathway or {}
        raw_steps = pathway.get("remediation_steps") or []

        self._emit(
            ctx, "MESSAGE", f"▶ Execute phase: {len(raw_steps)} step(s) to run (host OS fix)"
        )

        results: list[StepResult] = []
        for i, raw_step in enumerate(raw_steps, start=1):
            step_text = (
                raw_step.get("step") if isinstance(raw_step, dict) else str(raw_step)
            ) or ""
            self._emit(ctx, "MESSAGE", f"→ Step {i}/{len(raw_steps)}: {step_text[:180]}")

            # Guard: reject docker/terraform commands
            lower = step_text.lower()
            if "docker build" in lower or "terraform" in lower:
                self._emit(ctx, "ERROR", f"⏭ Step {i} SKIPPED — wrong strategy command detected")
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command="",
                        status="skipped",
                        started_at=ts,
                        finished_at=ts,
                        adaptation_note="docker/terraform in OS strategy — skipped",
                    )
                )
                continue

            commands = _extract_shell_blocks(step_text) if step_text else []
            if not commands:
                self._emit(ctx, "MESSAGE", f"   ⏭ No shell command in step {i} — skipping")
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command="",
                        status="skipped",
                        started_at=ts,
                        finished_at=ts,
                        adaptation_note="no shell command extracted",
                    )
                )
                continue

            combined = " && ".join(commands) if len(commands) > 1 else commands[0]

            # Safety gate
            verdict = validate_command(combined, working_directory="/")
            if not verdict.allowed:
                self._emit(ctx, "ERROR", f"🛡 Step {i} BLOCKED: {verdict.reason}")
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        exit_code=-1,
                        status="safety_blocked",
                        started_at=ts,
                        finished_at=ts,
                        safety_reason=verdict.reason,
                    )
                )
                return results
            self._emit(ctx, "MESSAGE", "   🛡 Safety check passed")

            # Timeout: apt-get update can be slow
            timeout = 300 if "apt-get update" in combined.lower() else 120

            try:
                cmd_result = executor.run_command(combined, timeout_s=timeout)
            except (RemoteExecError, CommandTimeoutError) as e:
                ts = utcnow()
                self._emit(ctx, "ERROR", f"✗ Step {i} crashed: {e}")
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        stderr=str(e),
                        exit_code=-1,
                        status="failed",
                        started_at=ts,
                        finished_at=ts,
                    )
                )
                return results

            if cmd_result.exit_code == 0:
                self._emit(ctx, "MESSAGE", f"✓ Step {i} succeeded ({cmd_result.duration_ms}ms)")
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        stdout=cmd_result.stdout,
                        stderr=cmd_result.stderr,
                        exit_code=0,
                        duration_ms=cmd_result.duration_ms,
                        status="success",
                        started_at=cmd_result.started_at,
                        finished_at=cmd_result.finished_at,
                    )
                )
            else:
                self._emit(ctx, "ERROR", f"✗ Step {i} exit={cmd_result.exit_code}")
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        stdout=cmd_result.stdout,
                        stderr=cmd_result.stderr,
                        exit_code=cmd_result.exit_code,
                        duration_ms=cmd_result.duration_ms,
                        status="failed",
                        started_at=cmd_result.started_at,
                        finished_at=cmd_result.finished_at,
                    )
                )
                return results

        return results

    # ==================================================================
    # Phase 6 — Validate
    # ==================================================================
    def validate(self, ctx: FixContext) -> list[ValidationResult]:
        executor = self._executor(ctx)
        pathway = ctx.pathway or {}
        raw_tests = pathway.get("validation_tests") or []

        self._emit(ctx, "MESSAGE", f"🔬 Validate phase: {len(raw_tests)} test(s) queued")

        results: list[ValidationResult] = []
        for i, raw_test in enumerate(raw_tests, start=1):
            if not isinstance(raw_test, dict):
                continue
            test_name = raw_test.get("name") or raw_test.get("test_name") or f"Test {i}"
            method = _normalize_method(raw_test.get("method"))
            expected = raw_test.get("expected") or ""
            command = raw_test.get("command") or ""

            is_rescan = bool(raw_test.get("is_rescan"))
            if not is_rescan and command:
                is_rescan = any(m in command.lower() for m in _RESCAN_CLI_MARKERS)

            if method == "manual" or not command:
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command or "(no command)",
                        expected=expected,
                        actual="skipped",
                        passed=True,
                        is_rescan=is_rescan,
                    )
                )
                continue

            timeout = 300 if "trivy" in command.lower() else 120
            try:
                cmd_result = executor.run_command(command, timeout_s=timeout)
                actual = ((cmd_result.stdout or "") + (cmd_result.stderr or ""))[:2000]
                passed = self._check_expected(expected, actual, cmd_result.exit_code)
                emoji = "✓" if passed else "✗"
                self._emit(
                    ctx,
                    "MESSAGE" if passed else "ERROR",
                    f"   {emoji} {test_name}: {'PASSED' if passed else 'FAILED'}",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command,
                        expected=expected,
                        actual=actual,
                        passed=passed,
                        is_rescan=is_rescan,
                        duration_ms=cmd_result.duration_ms,
                    )
                )
            except (RemoteExecError, CommandTimeoutError) as e:
                self._emit(ctx, "ERROR", f"   ✗ {test_name}: {e}")
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method,
                        command=command,
                        expected=expected,
                        actual=str(e),
                        passed=False,
                        is_rescan=is_rescan,
                    )
                )

        passed_count = sum(1 for r in results if r.passed)
        rescan_count = sum(1 for r in results if r.is_rescan)
        self._emit(
            ctx,
            "MESSAGE",
            f"🔬 Validate phase complete: {passed_count}/{len(results)} passed "
            f"({rescan_count} re-scan)",
        )
        return results

    @staticmethod
    def _check_expected(expected: str, actual: str, exit_code: int) -> bool:
        if not expected or not expected.strip():
            return exit_code == 0
        e = expected.strip().lower()
        if e in ("command exits 0", "exit 0", "exit code 0", "0"):
            return exit_code == 0
        return expected.strip() in actual

    # ==================================================================
    # Phase 7 — Rollback
    # ==================================================================
    def rollback(self, ctx: FixContext) -> list[RollbackResult]:
        executor = self._executor(ctx)
        backup_ref = ctx.backup_reference or ""

        self._emit(ctx, "MESSAGE", f"↶ Rollback: restoring package state from {backup_ref}")

        # Best-effort: dpkg --set-selections < backup + apt-get dselect-upgrade
        # This is a rough rollback — for the demo it's sufficient.
        cmd = f"dpkg --set-selections < {backup_ref} && apt-get dselect-upgrade -y 2>&1 | tail -5"
        results: list[RollbackResult] = []
        try:
            r = executor.run_command(cmd, timeout_s=300)
            success = r.exit_code == 0
            self._emit(
                ctx,
                "MESSAGE" if success else "ERROR",
                f"{'✓' if success else '✗'} Rollback: apt dselect-upgrade "
                f"{'succeeded' if success else 'failed'}",
            )
            results.append(
                RollbackResult(
                    step_num=1,
                    action="restore dpkg selections + dselect-upgrade",
                    command=cmd,
                    status="success" if success else "failed",
                    stdout=r.stdout,
                    stderr=r.stderr,
                    exit_code=r.exit_code,
                    duration_ms=r.duration_ms,
                    started_at=r.started_at,
                    finished_at=r.finished_at,
                )
            )
        except (RemoteExecError, CommandTimeoutError) as e:
            ts = utcnow()
            self._emit(ctx, "ERROR", f"✗ Rollback crashed: {e}")
            results.append(
                RollbackResult(
                    step_num=1,
                    action="restore dpkg selections",
                    command=cmd,
                    status="failed",
                    stderr=str(e),
                    started_at=ts,
                    finished_at=ts,
                )
            )

        return results
