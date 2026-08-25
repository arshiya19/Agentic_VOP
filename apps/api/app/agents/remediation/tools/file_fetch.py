"""File-fetch tool for the agentic Sub-Agent 3.

Given a file path on the target instance, SSMs into the instance and cats
the file. Feeds real current-state content back to SA-3 so the fix package
can reference actual resource names / values instead of hallucinating them.

Enterprise-scale rationale: this replaces the per-scanner "coordinated
generator" modules (checkov-only, trivy-image-only) with ONE generic tool
that any scanner prompt can invoke. Adding a new scanner = updating the
scanner's prompt to tell SA-3 which file(s) to fetch. No new code.

Returns a compact result the LLM can quote from directly:
  {
    "file_path": "/opt/vuln-labs/cspm-lab/main.tf",
    "instance_id": "i-06304a624808dea09",
    "content": "resource \"aws_s3_bucket\" ...",
    "content_length": 1832,
    "truncated": False,
    "exists": True,
    "elapsed_ms": 780,
  }

Guards:
  - 60s hard timeout on the SSM command
  - Max content size returned to LLM: 30_000 chars (raises with warning if larger)
  - Path safety: refuses shell metacharacters — path is quoted inside cat
  - Budget-aware: refuses if the agent's tool-call cap is already hit
  - Refuses when target_instance_id is unavailable (settings.fixer_env2_instance_id)
"""

from __future__ import annotations

import base64
import time
from typing import Any

import boto3

from ....config import settings
from .budget import AgentBudget


# Cap what we send back to the LLM. Terraform main.tf files rarely exceed
# a few KB; Dockerfiles are tiny; requirements.txt / pom.xml can be larger
# but 30 KB covers 99%+ of real-world cases and keeps us well under the
# model's context window even with several fetches in one run.
_MAX_CONTENT_CHARS = 30_000

# SSM command timeout — reads should complete in seconds; timeout catches
# hung instances or misconfigured SSM. Aligned with url_fetch's 15s but
# bumped to 60s because SSM has 2-3s of overhead before the shell runs.
_SSM_TIMEOUT_S = 60

# We refuse any path with shell metacharacters. The LLM should only pass
# straight absolute paths like /opt/vuln-labs/cspm-lab/main.tf. Anything
# fancier is either an injection attempt or a bad prompt.
_UNSAFE_PATH_CHARS = frozenset(";&|`$<>()\"'\\\n\r")


def fetch_file(
    file_path: str,
    budget: AgentBudget,
    *,
    target_instance_id: str | None = None,
    aws_region: str = "us-east-1",
    run_id: str | None = None,
    emit_fn=None,
) -> dict[str, Any]:
    """Read a file from the target instance via SSM.

    Raises RuntimeError on:
      - budget cap reached
      - unsafe path (shell metacharacters)
      - no target_instance_id configured
      - SSM send_command / invocation failure
      - file not present (returns dict with exists=False, does NOT raise)

    Args:
        file_path: absolute path to the file on the target instance.
        budget: shared per-run AgentBudget instance.
        target_instance_id: EC2 instance ID to SSM into. Falls back to
            settings.fixer_env2_instance_id for Phase-1 single-target
            deployments.
        aws_region: AWS region for the SSM client.
        run_id: agent_run_id for trace correlation.
        emit_fn: trace emitter (emit_trace or emit_trace_demo).
    """
    allowed, reason = budget.can_call()
    if not allowed:
        raise RuntimeError(f"file_fetch denied: {reason}")

    # Path safety — read-only tool, but still refuse metachars in the arg
    if any(c in _UNSAFE_PATH_CHARS for c in file_path):
        raise RuntimeError(f"file_fetch refused: path contains unsafe characters — {file_path!r}")
    if not file_path.startswith("/"):
        raise RuntimeError(f"file_fetch refused: path must be absolute — got {file_path!r}")

    instance_id = target_instance_id or settings.fixer_env2_instance_id
    if not instance_id:
        raise RuntimeError(
            "file_fetch denied: no target_instance_id and settings.fixer_env2_instance_id is empty"
        )

    if emit_fn and run_id:
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"📄 Fetching file: {file_path} (call {budget.call_count + 1}/{budget.max_calls})",
        )

    # Bundle the cat as a base64-encoded shell script so quoting is safe
    # end-to-end (matches the pattern in /admin/env2/reset and /admin/env2/status).
    # Emits a distinctive sentinel line if the file doesn't exist so we can
    # detect that case without ambiguity vs an empty-but-existing file.
    script = f"""#!/bin/bash
FILE={_shell_quote(file_path)}
if [ ! -f "$FILE" ]; then
  echo "__FILE_FETCH_NOT_FOUND__"
  exit 0
fi
cat "$FILE"
"""
    b64 = base64.b64encode(script.encode()).decode()
    ssm = boto3.client("ssm", region_name=aws_region)
    start = time.time()

    try:
        send = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            TimeoutSeconds=_SSM_TIMEOUT_S,
            Parameters={"commands": [f"echo {b64} | base64 -d | bash"]},
        )
    except Exception as e:  # noqa: BLE001
        budget.record_call("file_fetch")
        if emit_fn and run_id:
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"file_fetch send_command failed: {type(e).__name__}: {str(e)[:200]}",
            )
        raise RuntimeError(f"SSM send_command failed: {type(e).__name__}: {e}") from e

    command_id = send["Command"]["CommandId"]

    # Poll until the SSM invocation completes — SSM's 3-second minimum polling
    # is fine here because file reads are quick. Cap at ~45s wall-clock.
    deadline = time.time() + 45
    invocation = None
    while time.time() < deadline:
        try:
            invocation = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(1)
            continue
        if invocation["Status"] not in ("InProgress", "Pending", "Delayed"):
            break
        time.sleep(2)

    budget.record_call("file_fetch")
    elapsed_ms = int((time.time() - start) * 1000)

    if not invocation or invocation["Status"] != "Success":
        status = invocation["Status"] if invocation else "timeout"
        stderr = (invocation.get("StandardErrorContent") if invocation else "") or ""
        if emit_fn and run_id:
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"file_fetch SSM status={status}: {stderr[:200]}",
            )
        raise RuntimeError(f"file_fetch SSM invocation ended with status={status}: {stderr[:400]}")

    stdout = invocation.get("StandardOutputContent") or ""

    # File-not-found sentinel from our script — return a structured miss
    # instead of raising, so the LLM can decide what to do (fetch a
    # different file, fall back to web docs, etc.)
    if stdout.rstrip() == "__FILE_FETCH_NOT_FOUND__":
        if emit_fn and run_id:
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"⚠ file_fetch: {file_path} does not exist on {instance_id}",
            )
        return {
            "file_path": file_path,
            "instance_id": instance_id,
            "content": "",
            "content_length": 0,
            "truncated": False,
            "exists": False,
            "elapsed_ms": elapsed_ms,
        }

    # Truncate to what SA-3 can actually consume. Mark truncation so the
    # LLM knows the file was longer than what it can see (rare for IaC).
    truncated = False
    if len(stdout) > _MAX_CONTENT_CHARS:
        stdout = (
            stdout[:_MAX_CONTENT_CHARS]
            + f"\n\n[... truncated at {_MAX_CONTENT_CHARS} chars for LLM context budget ...]"
        )
        truncated = True

    if emit_fn and run_id:
        emit_fn(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"✓ Fetched {len(stdout)} chars from {file_path} in {elapsed_ms}ms"
            + (" (truncated)" if truncated else ""),
        )

    return {
        "file_path": file_path,
        "instance_id": instance_id,
        "content": stdout,
        "content_length": len(stdout),
        "truncated": truncated,
        "exists": True,
        "elapsed_ms": elapsed_ms,
    }


def _shell_quote(s: str) -> str:
    """Single-quote a path for safe inclusion in shell commands.

    We've already rejected metachars in `_UNSAFE_PATH_CHARS`, but wrap in
    single quotes as belt-and-suspenders. Escapes any embedded single
    quote by closing the quote, backslash-escaping the quote, and
    reopening. Standard POSIX shell trick.
    """
    return "'" + s.replace("'", "'\\''") + "'"
