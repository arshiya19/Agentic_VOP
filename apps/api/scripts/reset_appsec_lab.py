"""Reset appsec-lab source files on env2 to their pristine vulnerable state.

Usage:
    python apps/api/scripts/reset_appsec_lab.py              # restore files
    python apps/api/scripts/reset_appsec_lab.py --dry-run    # show what would change
    python apps/api/scripts/reset_appsec_lab.py --clean-bak  # also delete .bak-* files

Why this exists:
    SA-4 fix runs modify files under /opt/vuln-labs/appsec-lab/ directly.
    Once a run successfully fixes a vulnerability (debug=True → debug=False,
    md5 → sha256, etc.), the file stays modified. Subsequent runs try to
    fix findings that no longer exist — edit_file fails with "old_text not
    found" and the pipeline reports it as a rollback.

    For fair back-to-back demo runs we need the source files reset to their
    original vulnerable state. This script does that using the pristine
    copies committed in the repo at infra/vuln-labs/appsec-lab/.

    Universal (no fine-tuning): copies whatever files exist in that repo
    directory. Add a new source file to the lab? Commit it there; this
    script picks it up automatically. No hardcoded per-file logic.

Transport safety:
    Files are base64-encoded before going through SSM to avoid ANY shell
    parsing of the contents (same lesson as edit_file / verify_absent).
    Curly braces, quotes, backslashes, non-ASCII all pass through cleanly.
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

import boto3
from dotenv import load_dotenv


# Repo path (relative to this script) — the source of truth for pristine files
_REPO_APPSEC_LAB = Path(__file__).resolve().parents[3] / "infra" / "vuln-labs" / "appsec-lab"
# Target directory on env2
_ENV2_APPSEC_LAB = "/opt/vuln-labs/appsec-lab"


def _ssm_run(client, instance_id: str, command: str, timeout_s: int = 60) -> tuple[int, str, str]:
    """Send one shell command via SSM, poll until terminal, return (rc, stdout, stderr).

    Exceptions during send_command propagate (fail loudly on setup errors).
    Exceptions during the poll loop are tracked and surfaced if the poll
    never succeeds (avoids the "silent -1" failure mode).
    """
    try:
        resp = client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            TimeoutSeconds=max(30, timeout_s + 10),
            Parameters={"commands": [command]},
        )
    except Exception as e:  # noqa: BLE001
        return -1, "", f"send_command failed: {type(e).__name__}: {e}"
    cmd_id = resp["Command"]["CommandId"]
    deadline = time.time() + timeout_s + 15
    inv = None
    last_poll_err = None
    while time.time() < deadline:
        time.sleep(1.5)
        try:
            inv = client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except Exception as e:  # noqa: BLE001
            last_poll_err = f"{type(e).__name__}: {e}"
            continue
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            break
    if inv is None:
        return -1, "", f"SSM poll never succeeded (last error: {last_poll_err or 'unknown'})"
    if inv.get("Status") in ("Pending", "InProgress", "Delayed"):
        return -1, "", f"SSM command still {inv['Status']} after {timeout_s}s (cmd_id={cmd_id})"
    # BUG guard: SSM returns ResponseCode=0 on success, but `code or -1`
    # evaluates to -1 because 0 is falsy in Python. Use explicit None-check.
    rc_val = inv.get("ResponseCode")
    rc = int(rc_val) if rc_val is not None else -1
    return (
        rc,
        inv.get("StandardOutputContent", "") or "",
        inv.get("StandardErrorContent", "") or "",
    )


def _upload_file(client, instance_id: str, local_path: Path, remote_path: str) -> tuple[bool, str]:
    """Base64-encode local file, upload to remote_path via SSM. Returns (ok, message)."""
    content = local_path.read_bytes()
    b64 = base64.b64encode(content).decode("ascii")
    # Base64 payload is shell-safe (only A-Za-z0-9+/= chars).
    # Wrap the target path in single-quote-with-escape to survive any weird
    # characters (though target paths here are all plain).
    remote_shell = "'" + remote_path.replace("'", "'\\''") + "'"
    cmd = f"echo '{b64}' | base64 -d > {remote_shell} && stat -c '%s bytes' {remote_shell}"
    rc, stdout, stderr = _ssm_run(client, instance_id, cmd, timeout_s=30)
    if rc == 0:
        return True, stdout.strip()
    return False, (stderr.strip() or f"exit {rc}")


def _clean_backups(client, instance_id: str) -> tuple[bool, str]:
    """Delete all .bak-* files in the appsec-lab directory. Purely optional."""
    cmd = (
        f"count=$(find {_ENV2_APPSEC_LAB} -maxdepth 1 -name '*.bak-*' | wc -l) && "
        f"find {_ENV2_APPSEC_LAB} -maxdepth 1 -name '*.bak-*' -delete && "
        f'echo "deleted $count backup file(s)"'
    )
    rc, stdout, stderr = _ssm_run(client, instance_id, cmd, timeout_s=30)
    return rc == 0, (stdout.strip() if rc == 0 else stderr.strip() or f"exit {rc}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what files would be uploaded without actually doing it",
    )
    parser.add_argument(
        "--clean-bak",
        action="store_true",
        help="Also delete all .bak-* files in the appsec-lab dir after restoring",
    )
    parser.add_argument(
        "--instance-id",
        default=None,
        help="Target EC2 instance id. Defaults to FIXER_ENV2_INSTANCE_ID from .env",
    )
    args = parser.parse_args()

    # Load .env with override=True so values in .env win over anything already
    # set in the shell (default load_dotenv() would silently keep whatever the
    # shell has, which can point boto3 at a different account/profile entirely).
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)
    import os

    instance_id = args.instance_id or os.environ.get("FIXER_ENV2_INSTANCE_ID", "")
    if not instance_id:
        print("ERROR: no instance id — set FIXER_ENV2_INSTANCE_ID in .env or pass --instance-id")
        return 2

    if not _REPO_APPSEC_LAB.is_dir():
        print(f"ERROR: pristine source dir missing: {_REPO_APPSEC_LAB}")
        return 2

    # Enumerate what we'd upload (any file directly under the dir; skip subdirs)
    to_upload = sorted(f for f in _REPO_APPSEC_LAB.iterdir() if f.is_file())
    if not to_upload:
        print(f"ERROR: {_REPO_APPSEC_LAB} contains no files")
        return 2

    print(f"Target env2 instance: {instance_id}")
    print(f"Pristine source:      {_REPO_APPSEC_LAB}")
    print(f"Restore destination:  {_ENV2_APPSEC_LAB}")
    print(f"Files to restore:     {len(to_upload)}")
    for f in to_upload:
        print(f"  - {f.name}  ({f.stat().st_size} bytes)")

    if args.dry_run:
        print("\n(--dry-run — no changes made)")
        return 0

    # Pass credentials explicitly from env vars rather than letting boto3 fall
    # back to ~/.aws/credentials — that fallback can silently target a
    # different account whose IAM doesn't have SSM perms on our instance.
    client = boto3.client(
        "ssm",
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )

    # Verify SSM reachability first — fail fast if instance is unreachable
    print(f"\nSSM reachability check → sending echo READY to {instance_id}...")
    rc, stdout, stderr = _ssm_run(client, instance_id, "echo READY", timeout_s=15)
    print(f"  rc={rc!r}  stdout={stdout!r}  stderr={stderr!r}")
    if rc != 0:
        print(f"\nERROR: instance not reachable via SSM (rc={rc}): {stderr[:400]}")
        return 3

    print(f"\nRestoring {len(to_upload)} file(s)...")
    all_ok = True
    for local in to_upload:
        remote = f"{_ENV2_APPSEC_LAB}/{local.name}"
        ok, msg = _upload_file(client, instance_id, local, remote)
        status = "✓" if ok else "✗"
        print(f"  {status} {local.name} → {remote}  ({msg})")
        if not ok:
            all_ok = False

    if args.clean_bak:
        print("\nCleaning .bak-* files...")
        ok, msg = _clean_backups(client, instance_id)
        print(f"  {'✓' if ok else '✗'} {msg}")
        if not ok:
            all_ok = False

    print()
    if all_ok:
        print("✅ appsec-lab reset complete. Next demo run starts against pristine state.")
        return 0
    print("⚠ Some operations failed — check output above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
