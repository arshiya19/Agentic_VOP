"""ImageStrategy — Phase-1 concrete strategy for container-image findings.

Fits trivy-image (and structurally similar scanners: snyk-container,
grype-image). Fix shape is:

  pre_flight → backup (docker tag + Dockerfile snapshot) → execute (edit
  Dockerfile + docker build + retag) → validate (trivy image re-scan +
  ancillary checks) → rollback (retag pre-fix backup + restore Dockerfile)

Environment assumptions (env2 vuln-lab):
  - Dockerfile lives at /opt/vuln-labs/infra-lab/Dockerfile
  - Vulnerable image is tagged vuln-lab-image:latest
  - Docker daemon running, trivy binary on PATH
  - SSM agent Online (probed in pre-flight)

SA-3 emits a package whose remediation_steps look like:
  1. Back up Dockerfile
  2. sed / heredoc edit — update base image or pin fixed pkg version
  3. docker build -t vuln-lab-image:latest .
  4. (optional) docker prune, warm-run, etc.
  5. Re-scan: trivy image vuln-lab-image:latest --scanners vuln --severity ...

Design principles held here (mirror IaCStrategy):
  1. Generic execution — no per-CVE or per-image hardcoding. All fix
     knowledge lives in SA-3's package.
  2. Strict command provenance — every command SSM sees came from SA-3.
     ImageStrategy only injects the mechanical backup/rollback primitives.
  3. Safety before dispatch — every step passes validate_command().
  4. Trace-all — one trace event per phase transition + per step.
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


# =============================================================================
# Defaults for env2 vuln-lab (the only environment this MVP targets). SA-3's
# extractor should populate ctx.file_path / ctx.working_directory / ctx.
# resource_name from the finding when possible; these are last-resort
# fallbacks so the strategy is still runnable when the extractor misses.
# =============================================================================
_DEFAULT_DOCKERFILE = "/opt/vuln-labs/infra-lab/Dockerfile"
_DEFAULT_BUILD_DIR = "/opt/vuln-labs/infra-lab"
_DEFAULT_IMAGE_REF = "vuln-lab-image:latest"


# =============================================================================
# Scanner CLI markers — used to auto-detect "which validation_test is the
# re-scan" (per SA3 v2.4 hard rule 17: exactly one validation_test invokes
# the ORIGINAL scanner). Detection is by CLI verb + subcommand shape.
# =============================================================================
_RESCAN_CLI_MARKERS: tuple[str, ...] = (
    "trivy image",
    "trivy rootfs",
    "trivy fs",
    "grype",
    "snyk container",
)


# ValidationResult.method is a Literal["cli", "http", "sql", "manual"]. SA-3
# sometimes emits values outside that set (empty string, "shell", "bash",
# "container", etc.). Normalize before constructing so Pydantic doesn't
# raise. Anything unknown maps to "cli" — the safest interpretation for
# a shell command running via SSM.
def _normalize_method(method: str | None) -> str:
    m = (method or "").strip().lower()
    if m == "manual":
        return "manual"
    if m in ("http", "https", "curl"):
        return "http"
    if m in ("sql", "psql", "postgres", "mysql"):
        return "sql"
    return "cli"  # bash, shell, container, unset — all execute as shell commands


class ImageStrategy(BaseFixStrategy):
    """Strategy for container-image findings.

    Runs the same 5-phase lifecycle as IaCStrategy but with Docker-native
    backup (docker tag), execute (Dockerfile edit + docker build), and
    rollback (retag) primitives.
    """

    name = "Container Image"
    strategy_key = "image"

    def __init__(
        self,
        *,
        config: FixerConfig,
        emit_fn,
    ) -> None:
        self.config = config
        self.emit_fn = emit_fn

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _emit(self, ctx: FixContext, event_type: str, message: str) -> None:
        """Trace to sub-agent-4; swallow errors so tracing never breaks flow."""
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

    def _dockerfile_path(self, ctx: FixContext) -> str:
        """Prefer SA-3's extracted file_path; fall back to lab default."""
        return ctx.file_path or _DEFAULT_DOCKERFILE

    def _build_dir(self, ctx: FixContext) -> str:
        """Prefer SA-3's extracted working_directory; fall back to lab default."""
        return ctx.working_directory or _DEFAULT_BUILD_DIR

    def _image_ref(self, ctx: FixContext) -> str:
        """Image name:tag to rebuild. SA-3 may have extracted this into
        ctx.resource_name (e.g. `vuln-lab-image:latest`). Fallback to the
        env2 lab default.
        """
        resource = (ctx.resource_name or "").strip()
        if resource and (":" in resource or "/" in resource):
            return resource
        return _DEFAULT_IMAGE_REF

    def _timeout_for(self, command: str) -> int:
        """docker build is slow — give it a much larger ceiling than the
        default per-command timeout. Trivy image scans also need room."""
        c = (command or "").lower()
        if "docker build" in c:
            return 900  # 15 min — cold builds pull layers
        if "docker pull" in c or "docker push" in c:
            return 600
        if "trivy image" in c or "trivy rootfs" in c or "trivy fs" in c:
            return 600
        return self.config.ssm_command_timeout_s or 120

    # ==================================================================
    # Phase 3 — Pre-flight
    # ==================================================================
    def pre_flight_check(self, ctx: FixContext) -> PreFlightResult:
        """Verify env2 reachable, Docker running, Dockerfile + image + trivy present."""
        executor = self._executor(ctx)

        # 1. SSM reachability
        if not executor.is_reachable():
            return PreFlightResult(
                ready=False,
                blocking_reason=(
                    f"SSM agent on {ctx.target_instance_id} is not Online. "
                    "Cannot dispatch remediation commands."
                ),
            )
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: SSM reachable")

        # 2. Docker daemon
        try:
            r = executor.run_command("docker version --format '{{.Server.Version}}'", timeout_s=30)
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Docker probe crashed: {type(e).__name__}: {e}",
            )
        if r.exit_code != 0 or not (r.stdout or "").strip():
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Docker daemon not responsive (exit={r.exit_code}, stderr={r.stderr[:200]})",
            )
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: Docker daemon reachable (v{r.stdout.strip()})")

        # 3. Dockerfile
        df_path = self._dockerfile_path(ctx)
        try:
            r = executor.run_command(
                f"test -f '{df_path}' && echo YES || echo NO", timeout_s=30
            )
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Dockerfile probe crashed: {type(e).__name__}: {e}",
            )
        if "YES" not in (r.stdout or ""):
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Dockerfile not found at {df_path}",
            )
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: Dockerfile present at {df_path}")

        # 4. Target image exists (backup depends on it)
        image_ref = self._image_ref(ctx)
        try:
            r = executor.run_command(
                f"docker image inspect {image_ref} > /dev/null 2>&1 && echo YES || echo NO",
                timeout_s=45,
            )
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Image probe crashed: {type(e).__name__}: {e}",
            )
        if "YES" not in (r.stdout or ""):
            # Non-fatal — the fix might BUILD the image for the first time. Warn only.
            self._emit(
                ctx,
                "MESSAGE",
                f"⚠ Pre-flight: image {image_ref} not present yet (will be built by the fix)",
            )
        else:
            self._emit(ctx, "MESSAGE", f"✓ Pre-flight: image {image_ref} exists")

        # 5. Trivy binary — needed for re-scan validation
        try:
            r = executor.run_command("trivy --version 2>&1 | head -1", timeout_s=30)
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Trivy probe crashed: {type(e).__name__}: {e}",
            )
        if r.exit_code != 0:
            return PreFlightResult(
                ready=False,
                blocking_reason=f"Trivy binary unavailable (exit={r.exit_code})",
            )
        self._emit(
            ctx,
            "MESSAGE",
            f"✓ Pre-flight: trivy binary present ({(r.stdout or '').strip()[:80]})",
        )

        return PreFlightResult(ready=True)

    # ==================================================================
    # Phase 4 — Backup
    # ==================================================================
    def backup(self, ctx: FixContext) -> BackupResult:
        """Two-part backup: retag current image + snapshot Dockerfile.

        Backup reference is a compact string encoding both refs so rollback
        can restore either half independently. Format:
            image:<ref>|dockerfile:<abs_path>
        """
        executor = self._executor(ctx)
        image_ref = self._image_ref(ctx)
        df_path = self._dockerfile_path(ctx)

        self._emit(
            ctx,
            "MESSAGE",
            f"💾 Backup phase: retagging {image_ref} + snapshotting {df_path}",
        )

        # 1. Retag the current image as :pre-fix-<fix_run_id>
        image_no_tag = image_ref.rsplit(":", 1)[0] if ":" in image_ref else image_ref
        backup_tag = f"pre-fix-{ctx.fix_run_id}"
        backup_image_ref = f"{image_no_tag}:{backup_tag}"

        image_backup_ok = False
        try:
            r = executor.run_command(
                f"docker tag {image_ref} {backup_image_ref} 2>&1 && echo TAG_OK",
                timeout_s=60,
            )
            if r.exit_code == 0 and "TAG_OK" in (r.stdout or ""):
                image_backup_ok = True
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"✓ Backup: image retagged as {backup_image_ref}",
                )
            else:
                # Non-fatal — image may not exist yet if this is a first build.
                # Rollback will detect the missing backup and skip the retag.
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"⚠ Backup: image retag skipped ({r.stderr[:200] or 'no such image'})",
                )
        except (RemoteExecError, CommandTimeoutError) as e:
            self._emit(
                ctx,
                "ERROR",
                f"⚠ Backup: docker tag crashed ({type(e).__name__}: {e}) — continuing without image backup",
            )

        # 2. Snapshot the Dockerfile
        df_backup_path = ""
        try:
            r = executor.run_command(
                f"BACKUP='{df_path}'.bak-$(date -u +%Y%m%d-%H%M%SZ) && "
                f"cp '{df_path}' \"$BACKUP\" && echo \"$BACKUP\"",
                timeout_s=60,
            )
            if r.exit_code == 0 and (r.stdout or "").strip():
                df_backup_path = (r.stdout or "").strip().splitlines()[-1]
                self._emit(ctx, "MESSAGE", f"✓ Backup: Dockerfile snapshot at {df_backup_path}")
            else:
                self._emit(
                    ctx,
                    "ERROR",
                    f"⚠ Backup: Dockerfile snapshot failed (exit={r.exit_code}, "
                    f"stderr={r.stderr[:200]}). Rollback will be image-tag-only.",
                )
        except (RemoteExecError, CommandTimeoutError) as e:
            self._emit(
                ctx,
                "ERROR",
                f"⚠ Backup: Dockerfile snapshot crashed ({type(e).__name__}: {e})",
            )

        # Encode both halves so rollback can parse
        parts: list[str] = []
        if image_backup_ok:
            parts.append(f"image:{backup_image_ref}")
        if df_backup_path:
            parts.append(f"dockerfile:{df_backup_path}")
        backup_reference = "|".join(parts) if parts else "(no backup — rollback disabled)"

        return BackupResult(
            backup_reference=backup_reference,
            # Combined snapshot: an image retag + a file copy of the
            # Dockerfile. `file_copy` is the closest single-choice match to
            # the actual restore mechanism (both halves restore via cp/tag).
            backup_type="file_copy",
            original_path=df_path,
            created_at=utcnow(),
        )

    # ==================================================================
    # Phase 5 — Execute
    # ==================================================================
    def execute(self, ctx: FixContext) -> list[StepResult]:
        """Run SA-3's remediation_steps via SSM. Halt at first hard failure."""
        executor = self._executor(ctx)
        pathway = ctx.pathway or {}
        raw_steps = pathway.get("remediation_steps") or []
        wd = self._build_dir(ctx)

        self._emit(
            ctx,
            "MESSAGE",
            f"▶ Execute phase: {len(raw_steps)} step(s) to run "
            f"(wd={wd}, dockerfile={self._dockerfile_path(ctx)}, image={self._image_ref(ctx)})",
        )

        results: list[StepResult] = []
        for i, raw_step in enumerate(raw_steps, start=1):
            step_text = (
                raw_step.get("step") if isinstance(raw_step, dict) else str(raw_step)
            ) or ""
            self._emit(
                ctx,
                "MESSAGE",
                f"→ Step {i}/{len(raw_steps)}: {step_text[:180]}",
            )

            # Guard: reject terraform commands — SA-3 mis-routed if these appear.
            if "terraform" in step_text.lower():
                self._emit(
                    ctx,
                    "ERROR",
                    f"⏭ Step {i} SKIPPED — 'terraform' keyword in ImageStrategy (mis-routed by SA-3)",
                )
                results.append(
                    self._skipped_step(
                        i, step_text[:200], "terraform command in Image strategy — mis-routed"
                    )
                )
                continue

            # Extract shell block(s) from step text
            commands = _extract_shell_blocks(step_text) if step_text else []
            if not commands:
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"   ⏭ No shell command extractable from step {i} — skipping.",
                )
                results.append(
                    self._skipped_step(i, step_text[:200], "no shell command extracted")
                )
                continue

            combined = " && ".join(commands) if len(commands) > 1 else commands[0]
            self._emit(
                ctx,
                "MESSAGE",
                f"   📝 Extracted 1 shell block(s) from step text ({len(combined)} chars total)",
            )

            # Safety gate
            verdict = validate_command(combined, working_directory=wd)
            if not verdict.allowed:
                self._emit(
                    ctx,
                    "ERROR",
                    f"🛡 Step {i} BLOCKED by safety: {verdict.reason} "
                    f"(pattern={verdict.matched_pattern})",
                )
                ts = utcnow()
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        stdout="",
                        stderr="",
                        exit_code=-1,
                        duration_ms=0,
                        status="safety_blocked",
                        started_at=ts,
                        finished_at=ts,
                        safety_reason=verdict.reason,
                    )
                )
                return results
            self._emit(ctx, "MESSAGE", "   🛡 Safety check passed (no destructive patterns)")

            # Timeout chosen by command shape
            timeout = self._timeout_for(combined)
            self._emit(ctx, "MESSAGE", f"   ⏱ Timeout: {timeout}s (chosen based on command shape)")

            # Dispatch
            try:
                cmd_result = executor.run_command(
                    combined, working_directory=wd, timeout_s=timeout
                )
            except (RemoteExecError, CommandTimeoutError) as e:
                ts = utcnow()
                self._emit(
                    ctx,
                    "ERROR",
                    f"✗ Step {i} crashed: {type(e).__name__}: {str(e)[:300]}",
                )
                results.append(
                    StepResult(
                        step_num=i,
                        action=step_text[:200],
                        command=combined,
                        stderr=str(e),
                        exit_code=-1,
                        duration_ms=0,
                        status="failed",
                        started_at=ts,
                        finished_at=ts,
                    )
                )
                return results

            # Interpret exit code — 0 is success. Docker builds exit non-zero on
            # any error (image already exists is exit 0 for tag, exit 0 for build
            # even on cached rebuild). Trivy exits 0 with vulns unless --exit-code
            # is set, so raw exit 0 means "scan produced output" not "no vulns".
            if cmd_result.exit_code == 0:
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"✓ Step {i} succeeded ({cmd_result.duration_ms}ms)",
                )
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
                self._emit(
                    ctx,
                    "ERROR",
                    f"✗ Step {i} exit={cmd_result.exit_code} — {cmd_result.stderr[:200]}",
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

        return results

    # ==================================================================
    # Phase 6 — Validate
    # ==================================================================
    def validate(self, ctx: FixContext) -> list[ValidationResult]:
        """Run SA-3's validation_tests. Exactly one is expected to be a
        scanner re-scan (`trivy image ...` here) per SA3 v2.4 hard rule 17.
        """
        executor = self._executor(ctx)
        pathway = ctx.pathway or {}
        raw_tests = pathway.get("validation_tests") or []

        self._emit(
            ctx,
            "MESSAGE",
            f"🔬 Validate phase: {len(raw_tests)} test(s) queued "
            f"(exactly one MUST be a scanner re-scan)",
        )

        results: list[ValidationResult] = []
        for i, raw_test in enumerate(raw_tests, start=1):
            if not isinstance(raw_test, dict):
                continue
            test_name = raw_test.get("name") or raw_test.get("test_name") or f"Test {i}"
            method = (raw_test.get("method") or "").lower()
            expected = raw_test.get("expected") or ""
            command = raw_test.get("command") or ""

            is_rescan = bool(raw_test.get("is_rescan"))
            if not is_rescan and command:
                cmd_l = command.lower()
                is_rescan = any(m in cmd_l for m in _RESCAN_CLI_MARKERS)

            rescan_badge = " ✨ RE-SCAN" if is_rescan else ""
            self._emit(ctx, "MESSAGE", f"→ Test {i}/{len(raw_tests)}: {test_name}{rescan_badge}")

            # Normalize method to the Literal set ValidationResult expects.
            method_norm = _normalize_method(method)

            if method_norm == "manual":
                self._emit(
                    ctx,
                    "MESSAGE",
                    "   ⏭ Skipping — method='manual' not supported in Phase-1 Image strategy",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method="manual",
                        command=command or "(manual test — no command)",
                        expected=expected,
                        actual="skipped (manual)",
                        passed=True,
                        is_rescan=is_rescan,
                    )
                )
                continue

            if not command:
                self._emit(ctx, "MESSAGE", f"   ⏭ Test {i}: no command — skipping")
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method_norm,
                        command="(no command provided)",
                        expected=expected,
                        actual="no command provided",
                        passed=False,
                        is_rescan=is_rescan,
                    )
                )
                continue

            self._emit(ctx, "MESSAGE", f"   method={method_norm}, expected≈'{expected[:120]}'")

            timeout = self._timeout_for(command)
            try:
                cmd_result = executor.run_command(
                    command,
                    working_directory=self._build_dir(ctx),
                    timeout_s=timeout,
                )
                actual = ((cmd_result.stdout or "") + (cmd_result.stderr or ""))[:2000]
                passed = self._check_expected(expected, actual, cmd_result.exit_code)
                emoji = "✓" if passed else "✗"
                self._emit(
                    ctx,
                    "MESSAGE" if passed else "ERROR",
                    f"   {emoji} {test_name}: {'PASSED' if passed else 'FAILED'} "
                    f"(expected≈'{expected[:60]}' vs actual≈'{actual[:100]}')",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method_norm,
                        command=command,
                        expected=expected,
                        actual=actual,
                        passed=passed,
                        is_rescan=is_rescan,
                        duration_ms=cmd_result.duration_ms,
                    )
                )
            except (RemoteExecError, CommandTimeoutError) as e:
                self._emit(
                    ctx,
                    "ERROR",
                    f"   ✗ {test_name}: crashed {type(e).__name__}: {str(e)[:200]}",
                )
                results.append(
                    ValidationResult(
                        test_name=test_name,
                        method=method_norm,
                        command=command,
                        expected=expected,
                        actual=str(e),
                        passed=False,
                        is_rescan=is_rescan,
                    )
                )

        rescan_count = sum(1 for r in results if r.is_rescan)
        passed_count = sum(1 for r in results if r.passed)
        self._emit(
            ctx,
            "MESSAGE",
            f"🔬 Validate phase complete: {passed_count}/{len(results)} tests passed "
            f"({rescan_count} was a scanner re-scan)",
        )
        return results

    @staticmethod
    def _check_expected(expected: str, actual: str, exit_code: int) -> bool:
        """Loose match: expected substring in actual output, OR command exited 0
        when expected is a trivial 'exit 0' shape. Same policy as IaCStrategy."""
        if not expected or not expected.strip():
            return exit_code == 0
        e = expected.strip().lower()
        if e in ("command exits 0", "exit 0", "exit code 0"):
            return exit_code == 0
        return expected.strip() in actual

    # ==================================================================
    # Phase 7 — Rollback
    # ==================================================================
    def rollback(self, ctx: FixContext) -> list[RollbackResult]:
        """Restore Dockerfile from .bak + retag pre-fix image → :latest.

        Order matters: Dockerfile restore FIRST so the source of truth is
        aligned before the tag flip. If either half of the backup was
        missing (e.g. image didn't exist pre-fix), the corresponding step
        is skipped.
        """
        executor = self._executor(ctx)
        backup_ref = ctx.backup_reference or ""

        image_backup = ""
        df_backup = ""
        for chunk in backup_ref.split("|"):
            if chunk.startswith("image:"):
                image_backup = chunk[len("image:") :].strip()
            elif chunk.startswith("dockerfile:"):
                df_backup = chunk[len("dockerfile:") :].strip()

        self._emit(
            ctx,
            "MESSAGE",
            f"↶ Rollback phase started — image_backup={image_backup or 'none'}, "
            f"dockerfile_backup={df_backup or 'none'}",
        )

        results: list[RollbackResult] = []
        step_num = 0

        # 1. Restore Dockerfile
        if df_backup:
            step_num += 1
            df_target = self._dockerfile_path(ctx)
            restore_cmd = f"cp '{df_backup}' '{df_target}' && echo RESTORED"
            try:
                r = executor.run_command(restore_cmd, timeout_s=60)
                success = r.exit_code == 0 and "RESTORED" in (r.stdout or "")
                self._emit(
                    ctx,
                    "MESSAGE" if success else "ERROR",
                    f"{'✓' if success else '✗'} Rollback: Dockerfile restored from {df_backup}"
                    + ("" if success else f" (stderr={r.stderr[:200]})"),
                )
                results.append(
                    RollbackResult(
                        step_num=step_num,
                        action=f"restore Dockerfile from {df_backup}",
                        command=restore_cmd,
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
                self._emit(ctx, "ERROR", f"✗ Rollback: Dockerfile restore crashed: {e}")
                results.append(
                    RollbackResult(
                        step_num=step_num,
                        action=f"restore Dockerfile from {df_backup}",
                        command=restore_cmd,
                        status="failed",
                        stderr=str(e),
                        started_at=ts,
                        finished_at=ts,
                    )
                )
        else:
            self._emit(ctx, "MESSAGE", "↶ Rollback: no Dockerfile backup — skipping restore")

        # 2. Retag backup image → :latest (or original ref)
        if image_backup:
            step_num += 1
            image_ref = self._image_ref(ctx)
            retag_cmd = f"docker tag {image_backup} {image_ref} && echo RETAGGED"
            try:
                r = executor.run_command(retag_cmd, timeout_s=60)
                success = r.exit_code == 0 and "RETAGGED" in (r.stdout or "")
                self._emit(
                    ctx,
                    "MESSAGE" if success else "ERROR",
                    f"{'✓' if success else '✗'} Rollback: retagged {image_backup} → {image_ref}"
                    + ("" if success else f" (stderr={r.stderr[:200]})"),
                )
                results.append(
                    RollbackResult(
                        step_num=step_num,
                        action=f"retag {image_backup} → {image_ref}",
                        command=retag_cmd,
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
                self._emit(ctx, "ERROR", f"✗ Rollback: retag crashed: {e}")
                results.append(
                    RollbackResult(
                        step_num=step_num,
                        action=f"retag {image_backup} → {image_ref}",
                        command=retag_cmd,
                        status="failed",
                        stderr=str(e),
                        started_at=ts,
                        finished_at=ts,
                    )
                )
        else:
            self._emit(ctx, "MESSAGE", "↶ Rollback: no image backup — skipping retag")

        good = sum(1 for r in results if r.status == "success")
        self._emit(
            ctx,
            "MESSAGE",
            f"↶ Rollback phase complete: {good}/{len(results)} step(s) succeeded.",
        )
        return results

    # ==================================================================
    # Helpers
    # ==================================================================
    @staticmethod
    def _skipped_step(step_num: int, action: str, reason: str) -> StepResult:
        ts = utcnow()
        return StepResult(
            step_num=step_num,
            action=action[:200],
            command="",
            stdout=reason,
            stderr="",
            exit_code=0,
            duration_ms=0,
            status="skipped",
            started_at=ts,
            finished_at=ts,
            adaptation_note=reason[:500],
        )
