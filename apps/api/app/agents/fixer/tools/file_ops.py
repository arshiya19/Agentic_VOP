"""Remote file operations via SSM RunCommand.

Thin, typed wrapper on RemoteExecutor for the file-shaped primitives every
strategy needs:

  read_file    — cat the file, return contents (with size cap)
  write_file   — overwrite via heredoc (atomic on same fs)
  append_file  — append a block via heredoc (idempotent-with-marker pattern
                 available on caller demand)
  backup_file  — cp file → file.bak-{timestamp}, return the .bak path
  file_exists  — test -f, return bool

All operations are stateless — each call is a fresh SSM invocation. Safety
validation is caller's responsibility (validate_command before invoking any
write/append/backup — reads are already allowlist-checked via working_dir).
"""

from __future__ import annotations

from ..models import CommandResult
from .remote_exec import RemoteExecError, RemoteExecutor


# =============================================================================
# Read
# =============================================================================
def read_file(
    executor: RemoteExecutor,
    file_path: str,
    *,
    max_bytes: int = 200_000,
) -> str:
    """Read the file's contents from env2, capped at max_bytes.

    `max_bytes` protects against pathological outputs (multi-MB
    .terraform/plan files, log dumps). The LLM's context can't handle
    more than ~200KB anyway; further truncation happens at the strategy
    layer.
    """
    # `head -c` caps output at the source; no need to pipe through anything
    # else. Using -c (bytes) not -n (lines) so binary-safe.
    cmd = f"head -c {max_bytes} {file_path!r}"
    result = executor.run_command(cmd)
    if not result.succeeded:
        raise RemoteExecError(
            f"read_file({file_path!r}) failed exit={result.exit_code}: {result.stderr[:200]}"
        )
    return result.stdout


# =============================================================================
# Existence probe
# =============================================================================
def file_exists(executor: RemoteExecutor, file_path: str) -> bool:
    """Return True iff `file_path` exists on env2 (as a regular file)."""
    # -f = regular file (not directory, not symlink target missing)
    cmd = f"test -f {file_path!r} && echo YES || echo NO"
    result = executor.run_command(cmd)
    return result.succeeded and result.stdout.strip() == "YES"


def directory_exists(executor: RemoteExecutor, dir_path: str) -> bool:
    """Return True iff `dir_path` exists on env2 (as a directory)."""
    cmd = f"test -d {dir_path!r} && echo YES || echo NO"
    result = executor.run_command(cmd)
    return result.succeeded and result.stdout.strip() == "YES"


# =============================================================================
# Backup (used by every strategy's Phase A)
# =============================================================================
def backup_file(
    executor: RemoteExecutor,
    file_path: str,
) -> tuple[str, CommandResult]:
    """Copy `file_path` → `file_path.bak-YYYYMMDD-HHMMSS` on env2.

    Returns (backup_path, CommandResult). Strategy stores backup_path on
    the fix_run row so rollback can find it later.

    Timestamp is generated ON env2 (`$(date ...)`), not on the API host —
    keeps timestamps consistent with the target's clock, which matters if
    logs correlate across systems.
    """
    timestamp_expr = "$(date -u +%Y%m%d-%H%M%SZ)"

    # Emit the resolved backup path back on stdout so caller can capture it
    # (env2's timestamp, not the API host's).
    cmd = (
        f'BACKUP={file_path!r}.bak-{timestamp_expr} && cp {file_path!r} "$BACKUP" && echo "$BACKUP"'
    )
    result = executor.run_command(cmd)
    if not result.succeeded:
        raise RemoteExecError(
            f"backup_file({file_path!r}) failed exit={result.exit_code}: {result.stderr[:200]}"
        )

    backup_path = result.stdout.strip().splitlines()[-1] if result.stdout else ""
    if not backup_path:
        raise RemoteExecError(
            f"backup_file({file_path!r}) succeeded but produced no path on stdout: "
            f"{result.stdout!r}"
        )

    return backup_path, result


# =============================================================================
# Append (Phase B — the IaC edit primitive)
# =============================================================================
def append_file(
    executor: RemoteExecutor,
    file_path: str,
    content: str,
    *,
    heredoc_marker: str = "SISYFIX_EOF",
) -> CommandResult:
    """Append `content` to `file_path` on env2 via heredoc.

    Uses heredoc rather than `echo`/`printf` so the content — which
    includes newlines, quotes, `$` variable-ish tokens, and shell
    metacharacters (Terraform HCL loves `${...}` interpolation) — is
    passed verbatim without shell expansion.

    `heredoc_marker` is intentionally different from `EOF` to avoid
    collisions with content that legitimately contains the string `EOF`
    (e.g. Terraform outputs printing shell scripts).

    Note: the caller MUST have validated `content` via
    safety.validate_command AND worked out that the target file is on
    the allowlist. This function does no additional safety checking.
    """
    if heredoc_marker in content:
        raise ValueError(
            f"append_file: heredoc marker {heredoc_marker!r} appears in "
            "content — choose a different marker (this indicates the "
            "content might be adversarial or the caller picked a poor marker)"
        )

    # Wrap in ( ) so the whole heredoc is one unit; quote the marker so
    # inside the heredoc, no substitution happens.
    cmd = f"cat >> {file_path!r} << '{heredoc_marker}'\n{content}\n{heredoc_marker}"

    result = executor.run_command(cmd)
    if not result.succeeded:
        raise RemoteExecError(
            f"append_file({file_path!r}) failed exit={result.exit_code}: {result.stderr[:200]}"
        )
    return result


# =============================================================================
# Write (full overwrite — used less often than append; strategies prefer
# append-a-new-block over inline mutation because it preserves history)
# =============================================================================
def write_file(
    executor: RemoteExecutor,
    file_path: str,
    content: str,
    *,
    heredoc_marker: str = "SISYFIX_EOF",
) -> CommandResult:
    """Overwrite `file_path` with `content` on env2 via heredoc.

    Prefer `append_file` for IaC edits — full overwrites erase local
    comments/formatting the human wrote. Use only when the strategy has
    read + modified the file locally and wants to push the new state back.
    """
    if heredoc_marker in content:
        raise ValueError(f"write_file: heredoc marker {heredoc_marker!r} appears in content")

    cmd = f"cat > {file_path!r} << '{heredoc_marker}'\n{content}\n{heredoc_marker}"

    result = executor.run_command(cmd)
    if not result.succeeded:
        raise RemoteExecError(
            f"write_file({file_path!r}) failed exit={result.exit_code}: {result.stderr[:200]}"
        )
    return result


# =============================================================================
# Restore (rollback primitive — inverse of backup_file)
# =============================================================================
def restore_from_backup(
    executor: RemoteExecutor,
    original_path: str,
    backup_path: str,
) -> CommandResult:
    """Copy backup_path → original_path on env2 (used by rollback flow)."""
    cmd = f"cp {backup_path!r} {original_path!r}"
    result = executor.run_command(cmd)
    if not result.succeeded:
        raise RemoteExecError(
            f"restore_from_backup({backup_path!r} → {original_path!r}) failed "
            f"exit={result.exit_code}: {result.stderr[:200]}"
        )
    return result
