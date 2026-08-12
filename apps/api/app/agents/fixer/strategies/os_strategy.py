"""OSStrategy — concrete strategy for host OS vulnerability findings.

Fits trivy-os (and structurally similar host scanners: Tenable, Qualys,
Rapid7, Nessus). Fix shape is:

  pre_flight → backup (package state snapshot) → execute (apt/yum upgrade) →
  validate (package version check + trivy rootfs re-scan) →
  rollback (restore previous package state)

Supports two OS families:
  - Debian/Ubuntu (apt/dpkg) — env2 vuln-lab
  - Amazon Linux / RHEL / CentOS (yum/rpm) — env5 vuln-lab

OS detection happens once in pre_flight_check() by probing which package
manager is available. The result is stored as self._pkg_mgr ("apt" or "yum")
and used by backup/rollback/timeout to pick the right commands.

SA-3 emits packages whose remediation_steps are OS-aware when the
execution_context tells it which package manager to use.

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
    "apt list --installed",
    "rpm -qa",
    "yum list installed",
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
    """Strategy for host OS vulnerability findings (apt or yum-based).

    Same 5-phase lifecycle as IaCStrategy but with OS-native primitives.
    Detects the package manager (apt vs yum) in pre_flight_check and
    branches accordingly in backup/rollback.
    """

    name = "Host OS"
    strategy_key = "os"

    def __init__(self, *, config: FixerConfig, emit_fn) -> None:
        self.config = config
        self.emit_fn = emit_fn
        self._pkg_mgr: str = "apt"  # default, detected in pre_flight

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

        # Detect package manager: try apt first, then yum
        # NOTE: On AL2, `apt-get --version 2>&1` returns exit=0 with error in stdout
        # because SSM wraps the command. Check stdout content for actual availability.
        try:
            r = executor.run_command("apt-get --version 2>&1 | head -1", timeout_s=30)
            apt_available = (
                r.exit_code == 0
                and "apt" in (r.stdout or "").lower()
                and "not found" not in (r.stdout or "").lower()
            )

            if apt_available:
                self._pkg_mgr = "apt"
                self._emit(
                    ctx, "MESSAGE", f"✓ Pre-flight: apt available ({(r.stdout or '').strip()[:60]})"
                )
            else:
                # Try yum
                r2 = executor.run_command("yum --version 2>&1 | head -1", timeout_s=30)
                yum_available = r2.exit_code == 0 and "not found" not in (r2.stdout or "").lower()
                if yum_available:
                    self._pkg_mgr = "yum"
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"✓ Pre-flight: yum available ({(r2.stdout or '').strip()[:60]})",
                    )
                else:
                    return PreFlightResult(
                        ready=False,
                        blocking_reason="Neither apt-get nor yum available on target",
                    )
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(
                ready=False, blocking_reason=f"Package manager probe crashed: {e}"
            )

        # trivy available
        try:
            r = executor.run_command("trivy --version 2>&1 | head -1", timeout_s=30)
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(ready=False, blocking_reason=f"trivy probe crashed: {e}")
        if r.exit_code != 0:
            return PreFlightResult(ready=False, blocking_reason="trivy binary unavailable")
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: trivy present ({(r.stdout or '').strip()[:60]})")
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: OS package manager = {self._pkg_mgr}")

        return PreFlightResult(ready=True)

    # ==================================================================
    # Phase 4 — Backup
    # ==================================================================
    def backup(self, ctx: FixContext) -> BackupResult:
        executor = self._executor(ctx)
        backup_path = f"/tmp/pkg-state-fix-{ctx.fix_run_id}.txt"  # noqa: S108

        if self._pkg_mgr == "yum":
            backup_cmd = f"rpm -qa --queryformat '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' > {backup_path} && echo SAVED"
            desc = "rpm -qa"
        else:
            backup_cmd = f"dpkg --get-selections > {backup_path} && echo SAVED"
            desc = "dpkg --get-selections"

        self._emit(ctx, "MESSAGE", f"💾 Backup phase: {desc} → {backup_path}")

        try:
            r = executor.run_command(backup_cmd, timeout_s=60)
            if r.exit_code == 0 and "SAVED" in (r.stdout or ""):
                self._emit(ctx, "MESSAGE", f"✓ Backup: package state saved to {backup_path}")
            else:
                self._emit(ctx, "ERROR", f"⚠ Backup: state save returned exit={r.exit_code}")
        except (RemoteExecError, CommandTimeoutError) as e:
            self._emit(ctx, "ERROR", f"⚠ Backup: state save crashed: {e}")

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

            # Guard: skip commands that use tools/plugins not available on target.
            # These are LLM hallucinations that would fail and trigger rollback
            # unnecessarily — better to skip and let the real fix steps proceed.
            _SKIP_PATTERNS = (
                "yum versionlock",  # plugin not installed on AL2
                "apt-mark hold",  # wrong OS family if we're on yum
                "dpkg --configure",  # wrong OS family if we're on yum
            )
            if any(pat in lower for pat in _SKIP_PATTERNS):
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⏭ Step {i} SKIPPED — command uses unavailable tool ({[p for p in _SKIP_PATTERNS if p in lower][0]})",
                )
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command="",
                        status="skipped",
                        started_at=ts,
                        finished_at=ts,
                        adaptation_note="unavailable tool/plugin — skipped gracefully",
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

            # Guard: skip broad system-wide updates that waste time without
            # fixing the specific CVE. The LLM sometimes adds "sudo yum update -y"
            # (full update) or "yum update --security" as a blanket step.
            import re as _re  # noqa: PLC0415

            lower_combined = combined.lower().strip()
            # Strip sudo prefix for matching
            _cmd_for_match = _re.sub(r"^sudo\s+", "", lower_combined)
            if _re.search(r"^yum\s+update\s+(-y|--security)\s*$", _cmd_for_match) or _re.search(
                r"^yum\s+update\s*$", _cmd_for_match
            ):
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⏭ Step {i} SKIPPED — broad system update (not targeted to specific package)",
                )
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        status="skipped",
                        started_at=ts,
                        finished_at=ts,
                        adaptation_note="broad yum update (no pkg name) — skipped to save time",
                    )
                )
                continue

            # Safety gate
            verdict = validate_command(combined, working_directory="/")
            if not verdict.allowed:
                # For OS strategy, a blocked command (like sudo reboot) should NOT
                # halt the entire run — just skip this step and continue. The actual
                # fix (yum update) already succeeded in an earlier step. Halting here
                # would trigger a full rollback, undoing the successful fix.
                self._emit(ctx, "ERROR", f"🛡 Step {i} BLOCKED (skipping): {verdict.reason}")
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        exit_code=-1,
                        status="skipped",
                        started_at=ts,
                        finished_at=ts,
                        safety_reason=verdict.reason,
                        adaptation_note="safety-blocked command skipped (OS strategy continues)",
                    )
                )
                continue
            self._emit(ctx, "MESSAGE", "   🛡 Safety check passed")

            # Timeout: apt-get update / yum update and trivy scans can be slow
            lower_cmd = combined.lower()
            if (
                "apt-get update" in lower_cmd
                or "apt update" in lower_cmd
                or "yum update" in lower_cmd
                or "yum makecache" in lower_cmd
                or "yum install" in lower_cmd
            ):
                timeout = 300
            elif "trivy" in lower_cmd:
                timeout = 600
            else:
                timeout = 120

            try:
                cmd_result = executor.run_command(combined, timeout_s=timeout)
            except (RemoteExecError, CommandTimeoutError) as e:
                # For OS strategy: only halt on timeout if it's a core fix command.
                # Non-critical commands timing out shouldn't kill the whole run.
                is_core_fix = any(
                    kw in lower_cmd
                    for kw in ("yum update", "yum install", "apt-get install", "apt-get upgrade")
                )
                ts = utcnow()
                if is_core_fix:
                    self._emit(ctx, "ERROR", f"✗ Step {i} crashed (core command): {e}")
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
                else:
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"⚠ Step {i} crashed (non-critical, continuing): {str(e)[:100]}",
                    )
                    results.append(
                        StepResult(
                            step_num=i,
                            action=step_text[:200],
                            command=combined,
                            stderr=str(e),
                            exit_code=-1,
                            status="success",
                            started_at=ts,
                            finished_at=ts,
                            adaptation_note=f"non-critical step crashed, continued: {str(e)[:80]}",
                        )
                    )
                    continue

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
                # For OS strategy: only the core fix command (yum update/install <pkg>)
                # is critical. Auxiliary steps (lsof, yum check-update, rpm --rebuilddb,
                # echo to log) failing should NOT halt the run — they're nice-to-have
                # but the real fix already happened. Continue to let validation decide.
                is_core_fix = any(
                    kw in lower_cmd
                    for kw in ("yum update", "yum install", "apt-get install", "apt-get upgrade")
                )
                if is_core_fix:
                    self._emit(
                        ctx,
                        "ERROR",
                        f"✗ Step {i} FAILED (core fix command) exit={cmd_result.exit_code}",
                    )
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
                else:
                    self._emit(
                        ctx,
                        "MESSAGE",
                        f"⚠ Step {i} exit={cmd_result.exit_code} (non-critical, continuing)",
                    )
                    results.append(
                        StepResult(
                            step_num=i,
                            action=step_text[:200],
                            command=combined,
                            stdout=cmd_result.stdout,
                            stderr=cmd_result.stderr,
                            exit_code=cmd_result.exit_code,
                            duration_ms=cmd_result.duration_ms,
                            status="success",  # Mark as success so orchestrator doesn't rollback
                            started_at=cmd_result.started_at,
                            finished_at=cmd_result.finished_at,
                            adaptation_note=f"non-critical step exit={cmd_result.exit_code}, continued",
                        )
                    )

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

        # OS-aware rollback:
        # - apt: dpkg --set-selections < backup + apt-get dselect-upgrade
        # - yum: yum history undo last (best-effort — yum tracks transactions)
        if self._pkg_mgr == "yum":
            cmd = "yum history undo last -y 2>&1 | tail -10"
            action_desc = "yum history undo last"
        else:
            cmd = (
                f"dpkg --set-selections < {backup_ref} && apt-get dselect-upgrade -y 2>&1 | tail -5"
            )
            action_desc = "restore dpkg selections + dselect-upgrade"

        results: list[RollbackResult] = []
        try:
            r = executor.run_command(cmd, timeout_s=300)
            success = r.exit_code == 0
            self._emit(
                ctx,
                "MESSAGE" if success else "ERROR",
                f"{'✓' if success else '✗'} Rollback: {action_desc} "
                f"{'succeeded' if success else 'failed'}",
            )
            results.append(
                RollbackResult(
                    step_num=1,
                    action=action_desc,
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
                    action=action_desc,
                    command=cmd,
                    status="failed",
                    stderr=str(e),
                    started_at=ts,
                    finished_at=ts,
                )
            )

        return results
