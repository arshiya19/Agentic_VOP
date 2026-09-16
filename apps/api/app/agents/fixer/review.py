"""HITL v2 post-fix review — diff capture + backup restore helpers.

Companion to the post-fix review flow (see design doc: Post-Fix Review Modes,
Approach A · Sandbox). Two primitives:

  capture_review_diff  — after SA-4's validate passes, read the current file
                         AND the backup file via SSM, compute a unified diff,
                         return a JSONB-shaped record.

  restore_from_backup  — used by the Reject endpoint to un-apply an approved
                         change. Copies the .bak back over the original.

Deliberately minimal — the diff is a single file case (IaC / code_edit /
dependency strategies edit one file per fix). Multi-file support is a Phase
2 concern; the record is already a LIST so the shape extends without
schema churn.
"""

from __future__ import annotations

import difflib
from typing import Any

from .tools.remote_exec import CommandTimeoutError, RemoteExecError, RemoteExecutor


# Cap per-file content we send to the UI. 512 KB is far more than any
# Terraform / source file we'll realistically edit, and prevents an
# accidentally huge log-tail from bloating the fix_run row.
_MAX_FILE_BYTES = 512 * 1024


def capture_review_diff(
    executor: RemoteExecutor,
    *,
    current_path: str,
    backup_path: str,
) -> list[dict] | None:
    """Read the current + backup file via SSM, return a diff record.

    Returns a list with one dict (kept as a list for future multi-file
    support) shaped like:

        [
          {
            "file_path": "/opt/vuln-labs/cspm-lab/main.tf",
            "before": "<full backup contents>",
            "after":  "<full current contents>",
            "unified_diff": "<git-style unified diff>",
            "bytes_before": 4102,
            "bytes_after":  4351,
          }
        ]

    Returns None on any SSM error — the caller degrades to "no diff shown"
    rather than blocking the flow. Diff capture is a nice-to-have; the fix
    itself is authoritative.
    """
    if not current_path or not backup_path:
        return None

    # Compound backup_reference (image strategy) packs an image tag and
    # a Dockerfile path. Only the Dockerfile portion is a real filesystem
    # path we can cat + diff. Extract it before reading.
    read_backup_path = backup_path
    if "|" in backup_path or backup_path.startswith(("image:", "dockerfile:")):
        for chunk in backup_path.split("|"):
            if chunk.startswith("dockerfile:"):
                read_backup_path = chunk[len("dockerfile:") :].strip()
                break
        else:
            return None  # compound but no dockerfile chunk → nothing to diff

    try:
        before = _read_file(executor, read_backup_path)
        after = _read_file(executor, current_path)
    except (RemoteExecError, CommandTimeoutError):
        return None

    if before is None or after is None:
        return None

    unified = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"{current_path} (before)",
            tofile=f"{current_path} (after)",
            lineterm="",
            n=5,  # context lines — enough to show intent, not overwhelming
        )
    )

    return [
        {
            "file_path": current_path,
            "before": before[:_MAX_FILE_BYTES],
            "after": after[:_MAX_FILE_BYTES],
            "unified_diff": unified[: _MAX_FILE_BYTES * 2],
            "bytes_before": len(before),
            "bytes_after": len(after),
        }
    ]


def restore_backup_via_ssm(
    executor: RemoteExecutor,
    *,
    current_path: str,
    backup_path: str,
) -> tuple[bool, str]:
    """Restore whatever the backup_reference references. Used by Reject.

    Handles two shapes:

    1. **Plain path** — IaC / code_edit / dependency / OS strategies store
       a single `.bak` file path. We `cp {backup} {current}`.

    2. **Compound (image strategy)** — a `|`-separated bundle like
       `image:vuln-lab-image:pre-fix-2576|dockerfile:/opt/.../Dockerfile.bak-...`.
       We split on `|`, restore the Dockerfile via `cp`, AND retag the
       backup docker image back to `:latest`. Both operations are needed —
       restoring only the Dockerfile leaves the built image with the fix.

    Returns (ok, message). Never raises.
    """
    if not backup_path:
        return False, "missing backup_path"

    # Detect + handle the compound image-strategy format.
    if "|" in backup_path or backup_path.startswith(("image:", "dockerfile:")):
        return _restore_image_compound(executor, backup_path, current_path=current_path)

    # Plain file backup — single cp is enough.
    if not current_path:
        return False, "missing current_path for plain-file restore"
    cmd = f"cp {backup_path!r} {current_path!r} && echo RESTORED"
    try:
        r = executor.run_command(cmd, timeout_s=60)
    except (RemoteExecError, CommandTimeoutError) as e:
        return False, f"SSM error: {type(e).__name__}: {str(e)[:200]}"
    if r.exit_code != 0 or "RESTORED" not in (r.stdout or ""):
        return False, f"restore failed (exit={r.exit_code}): {(r.stderr or r.stdout or '')[:200]}"
    return True, "restored"


def _restore_image_compound(
    executor: RemoteExecutor,
    backup_ref: str,
    *,
    current_path: str = "",
) -> tuple[bool, str]:
    """Handle the image-strategy compound backup format:
        image:<pre-fix-image-tag>|dockerfile:<abs-path-to-Dockerfile-bak>

    Restore order matches ImageStrategy.rollback:
      1. cp Dockerfile.bak → Dockerfile   (source of truth first)
      2. docker tag <backup-image> → :latest   (aligns the built image)

    Either half missing → its step is skipped, not a failure. But if
    BOTH are missing, we can't do anything → return failure.
    """
    image_backup = ""
    df_backup = ""
    for chunk in backup_ref.split("|"):
        if chunk.startswith("image:"):
            image_backup = chunk[len("image:") :].strip()
        elif chunk.startswith("dockerfile:"):
            df_backup = chunk[len("dockerfile:") :].strip()

    if not image_backup and not df_backup:
        return False, f"could not parse backup_reference: {backup_ref[:100]!r}"

    steps: list[str] = []

    # 1. Restore Dockerfile — prefer the caller-supplied `current_path`
    #    (comes from fix_run.target_file_path, always accurate). Fall back
    #    to stripping `.bak-<timestamp>` from the backup name if it wasn't
    #    passed in.
    if df_backup:
        target = current_path
        if not target and ".bak-" in df_backup:
            target = df_backup.split(".bak-")[0]
        if not target:
            return False, f"cannot determine Dockerfile restore target from {df_backup!r}"
        cmd = f"cp {df_backup!r} {target!r} && echo DF_RESTORED"
        try:
            r = executor.run_command(cmd, timeout_s=60)
            if r.exit_code == 0 and "DF_RESTORED" in (r.stdout or ""):
                steps.append(f"Dockerfile restored ({df_backup} → {target})")
            else:
                return (
                    False,
                    f"Dockerfile restore failed (exit={r.exit_code}): "
                    f"{(r.stderr or r.stdout or '')[:200]}",
                )
        except (RemoteExecError, CommandTimeoutError) as e:
            return False, f"Dockerfile restore SSM error: {type(e).__name__}: {str(e)[:200]}"

    # 2. Retag backup image → :latest. The backup tag format is
    #    `<repo>:pre-fix-<fix_run_id>`. The live tag is `<repo>:latest`.
    if image_backup:
        repo = image_backup.rsplit(":", 1)[0] if ":" in image_backup else image_backup
        live_tag = f"{repo}:latest"
        cmd = f"docker tag {image_backup!r} {live_tag!r} && echo TAG_RESTORED"
        try:
            r = executor.run_command(cmd, timeout_s=60)
            if r.exit_code == 0 and "TAG_RESTORED" in (r.stdout or ""):
                steps.append(f"image retagged ({image_backup} → {live_tag})")
            else:
                # Dockerfile restore already succeeded; report as partial.
                return (
                    False,
                    f"image retag failed (exit={r.exit_code}): "
                    f"{(r.stderr or r.stdout or '')[:200]}. "
                    f"NOTE: Dockerfile was already restored — only the "
                    f"docker image tag remains at post-fix state.",
                )
        except (RemoteExecError, CommandTimeoutError) as e:
            return (
                False,
                f"image retag SSM error: {type(e).__name__}: {str(e)[:200]}",
            )

    return True, "; ".join(steps) or "nothing to restore"


def delete_backup_via_ssm(executor: RemoteExecutor, backup_path: str) -> None:
    """Best-effort cleanup on Approve. Handles both plain and compound
    backup_reference. Failure is non-fatal — a lingering backup is a
    rounding-error space cost.

    For the image-strategy compound `image:<tag>|dockerfile:<path>`, we
    only clean up the Dockerfile .bak — the pre-fix docker image tag is
    left intact so it stays available if needed for forensics.
    """
    if not backup_path:
        return
    paths_to_rm: list[str] = []
    if "|" in backup_path or backup_path.startswith(("image:", "dockerfile:")):
        for chunk in backup_path.split("|"):
            if chunk.startswith("dockerfile:"):
                paths_to_rm.append(chunk[len("dockerfile:") :].strip())
    else:
        paths_to_rm.append(backup_path)
    for p in paths_to_rm:
        if not p:
            continue
        try:
            executor.run_command(f"rm -f {p!r}", timeout_s=30)
        except Exception:  # noqa: BLE001, S112
            continue


# =============================================================================
# Internal — SSM file read
# =============================================================================
def _read_file(executor: RemoteExecutor, path: str) -> str | None:
    """Read a file over SSM via base64-encoded cat.

    Base64 keeps binary safety and avoids shell quoting nightmares. The
    output shape lets us detect a missing file cleanly (exit != 0).
    """
    # Use base64 -w0 (Ubuntu / Debian) with a fallback for BSD tools that
    # don't have -w. cat FIRST so a missing file fails fast on cat.
    cmd = f"cat {path!r} 2>/dev/null | base64 -w0 2>/dev/null || cat {path!r} | base64"
    try:
        r = executor.run_command(cmd, timeout_s=60)
    except (RemoteExecError, CommandTimeoutError):
        return None
    if r.exit_code != 0:
        return None
    import base64  # noqa: PLC0415

    try:
        return base64.b64decode(r.stdout or "").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None


def _persist_diff(sb: Any, fix_run_id: int, diff: list[dict] | None) -> None:
    """Write review_diff JSONB onto the fix_run row. Best-effort — a DB
    hiccup here shouldn't block finalize."""
    if diff is None:
        return
    try:
        sb.table("fix_runs").update({"review_diff": diff}).eq("id", fix_run_id).execute()
    except Exception:  # noqa: BLE001, S110
        pass


# Public re-export for the orchestrator + endpoints.
persist_diff = _persist_diff
