"""SSM RunCommand wrapper — how Sub-Agent 4 executes anything on env2.

We deliberately do NOT SSH. AWS SSM RunCommand gives us:
  - No long-lived credentials on either instance (IAM roles + STS)
  - Full CloudTrail audit for every invocation
  - Native output capture (no stdout/stderr multiplexing quirks)
  - Works even when env2 has no public IP / no ingress

Wrapper responsibilities:
  1. Serialize a command → SSM SendCommand
  2. Poll GetCommandInvocation until terminal status
  3. Materialize a CommandResult (typed) for the strategy layer
  4. Wrap SSM-specific errors in RemoteExecError (uniform failure mode)

Everything a strategy does on env2 flows through here. There is no other
path to env2 from the fixer.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..config import FixerConfig
from ..models import CommandResult, utcnow

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient  # type: ignore[import-untyped]


# =============================================================================
# Errors
# =============================================================================
class RemoteExecError(RuntimeError):
    """Raised when SSM invocation fails for a reason unrelated to the command
    itself (network, IAM, instance unreachable, throttling exhausted).

    NOT raised for non-zero exit codes — those are legitimate command
    outcomes and return via CommandResult.exit_code."""


class CommandTimeoutError(RemoteExecError):
    """Command exceeded its per-invocation timeout."""


# =============================================================================
# Terminal SSM statuses
# =============================================================================
# See: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CommandInvocation.html
_TERMINAL_STATUSES = {"Success", "TimedOut", "Cancelled", "Failed"}
_TRANSIENT_STATUSES = {"Pending", "InProgress", "Delayed"}


# =============================================================================
# Client
# =============================================================================
class RemoteExecutor:
    """Execute shell commands on a target EC2 via SSM RunCommand.

    One RemoteExecutor is bound to one instance-id + region. Reuse across
    multiple commands within a fix run — cheap because boto3 clients are
    connection-pooled.

    Not thread-safe — callers must serialize invocations.
    """

    def __init__(
        self,
        instance_id: str,
        *,
        region: str,
        config: FixerConfig,
        ssm_client: "SSMClient | None" = None,
    ) -> None:
        if not instance_id:
            raise ValueError("RemoteExecutor requires a non-empty instance_id")
        self.instance_id = instance_id
        self.region = region
        self.config = config
        # ssm_client is injectable for tests + LocalStack integration
        self._ssm: "SSMClient" = ssm_client or boto3.client("ssm", region_name=region)

    # =========================================================================
    # Reachability probe
    # =========================================================================
    def is_reachable(self) -> bool:
        """Return True if the SSM agent on env2 is online + responding.

        Uses DescribeInstanceInformation rather than a no-op RunCommand
        so we don't record a spurious invocation in CloudTrail every time
        we do a pre-flight check.
        """
        try:
            resp = self._ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [self.instance_id]}]
            )
            infos = resp.get("InstanceInformationList", []) or []
            if not infos:
                return False
            status = (infos[0] or {}).get("PingStatus")
            return status == "Online"
        except (ClientError, BotoCoreError):
            return False

    # =========================================================================
    # Command execution — the main API
    # =========================================================================
    def run_command(
        self,
        command: str,
        *,
        working_directory: str | None = None,
        timeout_s: int | None = None,
    ) -> CommandResult:
        """Send `command` to env2 via SSM RunCommand, wait for completion,
        return a CommandResult.

        Args:
            command:            The shell command to run (single string; multi-line
                                heredocs and && chains are fine).
            working_directory:  If given, wrapped as `cd <dir> && (command)` so
                                the invocation runs in the expected directory.
                                Safety-checked upstream by the caller.
            timeout_s:          Per-invocation timeout override. Falls back to
                                config.ssm_command_timeout_s.

        Returns:
            CommandResult — succeeded property is (exit_code == 0).
            A non-zero exit code is NOT an exception; it's a legitimate
            outcome the strategy interprets.

        Raises:
            RemoteExecError — SSM API failure (throttled after retries,
                              instance unreachable, IAM denied, etc.)
            CommandTimeoutError — command status was TimedOut after polling.
        """
        eff_timeout = timeout_s or self.config.ssm_command_timeout_s
        wrapped = self._wrap_with_cd(command, working_directory)

        # 1. Dispatch
        command_id = self._send_command(wrapped, eff_timeout)
        started_at = utcnow()

        # 2. Poll to terminal
        invocation = self._poll_to_terminal(command_id, eff_timeout, started_at)
        finished_at = utcnow()

        # 3. Extract
        status = (invocation.get("Status") or "").strip()
        stdout = invocation.get("StandardOutputContent") or ""
        stderr = invocation.get("StandardErrorContent") or ""
        exit_code = int(invocation.get("ResponseCode") or 0)

        duration_ms = int((finished_at - started_at).total_seconds() * 1000)

        if status == "TimedOut":
            raise CommandTimeoutError(
                f"SSM command {command_id} on {self.instance_id} timed out after "
                f"{eff_timeout}s. Partial stdout ({len(stdout)} chars): {stdout[:200]!r}"
            )

        return CommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=duration_ms,
            started_at=started_at,
            finished_at=finished_at,
            ssm_command_id=command_id,
        )

    # =========================================================================
    # Internal — SendCommand with transient-retry
    # =========================================================================
    def _send_command(self, wrapped_command: str, execution_timeout_s: int) -> str:
        """Dispatch to SSM. Retry only on transient AWS errors (throttling,
        RequestLimitExceeded). Application errors surface via CommandResult
        instead.
        """
        retries = self.config.ssm_transient_retries
        backoff = self.config.ssm_retry_backoff_s

        for attempt in range(retries + 1):
            try:
                resp = self._ssm.send_command(
                    InstanceIds=[self.instance_id],
                    DocumentName=self.config.ssm_document_name,
                    Parameters={
                        "commands": [wrapped_command],
                        # ExecutionTimeout is a STRING per AWS API (weird but true)
                        "executionTimeout": [str(execution_timeout_s)],
                    },
                    TimeoutSeconds=execution_timeout_s,
                )
                cmd_id = ((resp.get("Command") or {}).get("CommandId"))
                if not cmd_id:
                    raise RemoteExecError(
                        f"SSM SendCommand returned no CommandId (resp: {resp!r})"
                    )
                return cmd_id
            except ClientError as e:
                code = (e.response.get("Error") or {}).get("Code", "")
                is_transient = code in {
                    "ThrottlingException",
                    "RequestLimitExceeded",
                    "InternalServerError",
                }
                if attempt < retries and is_transient:
                    time.sleep(backoff * (attempt + 1))
                    continue
                raise RemoteExecError(
                    f"SSM SendCommand failed ({code}): {e}"
                ) from e
            except BotoCoreError as e:
                raise RemoteExecError(f"SSM connection error: {e}") from e

        # Unreachable
        raise RemoteExecError("SSM SendCommand exhausted retries without raising")

    # =========================================================================
    # Internal — poll invocation until terminal status or hard timeout
    # =========================================================================
    def _poll_to_terminal(
        self,
        command_id: str,
        soft_timeout_s: int,
        started_at,
    ) -> dict:
        """Poll GetCommandInvocation until Status is terminal.

        Two timeouts at play:
          - `soft_timeout_s`  — matches the SSM ExecutionTimeout we sent.
                                We give SSM a bit of grace beyond this
                                before considering the poll itself hung.
          - Hard cap          — `soft + 60s`. If SSM still hasn't marked the
                                command terminal by then, something is wrong
                                with SSM itself, not the command.
        """
        interval = self.config.ssm_poll_interval_s
        hard_cap_s = soft_timeout_s + 60

        # SSM's GetCommandInvocation can 404 momentarily right after SendCommand
        # returned. Retry the first read a few times.
        for _ in range(5):
            try:
                inv = self._ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=self.instance_id,
                )
                break
            except ClientError as e:
                if (e.response.get("Error") or {}).get("Code") == "InvocationDoesNotExist":
                    time.sleep(0.5)
                    continue
                raise RemoteExecError(f"SSM GetCommandInvocation failed: {e}") from e
        else:
            raise RemoteExecError(
                f"SSM invocation {command_id} did not become visible after retries"
            )

        # Poll to terminal
        while True:
            status = (inv.get("Status") or "").strip()
            if status in _TERMINAL_STATUSES:
                return inv

            elapsed = (utcnow() - started_at).total_seconds()
            if elapsed >= hard_cap_s:
                raise CommandTimeoutError(
                    f"SSM invocation {command_id} on {self.instance_id} still "
                    f"{status!r} after {int(elapsed)}s (hard cap {hard_cap_s}s)"
                )

            time.sleep(interval)

            try:
                inv = self._ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=self.instance_id,
                )
            except ClientError as e:
                raise RemoteExecError(
                    f"SSM GetCommandInvocation polling failed: {e}"
                ) from e

    # =========================================================================
    # Internal — command wrapping helpers
    # =========================================================================
    @staticmethod
    def _wrap_with_cd(command: str, working_directory: str | None) -> str:
        """Prepend `cd <working_directory> && ` if provided.

        We wrap in a subshell so the caller's command can use its own
        redirection operators without interfering with cd's exit status
        detection.
        """
        if not working_directory:
            return command
        # Parens create a subshell so the cd doesn't persist state we don't
        # want, and so multi-line commands work as one unit.
        return f"cd {working_directory!r} && ( {command} )"
