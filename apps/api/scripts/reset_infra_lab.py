"""Reset infra-lab Dockerfile + rebuild vuln-lab-image on env2.

Usage:
    python apps/api/scripts/reset_infra_lab.py               # full reset
    python apps/api/scripts/reset_infra_lab.py --dry-run     # show what would happen
    python apps/api/scripts/reset_infra_lab.py --skip-build  # only restore Dockerfile, skip docker build

Why this exists:
    SA-4 image fix runs modify /opt/vuln-labs/infra-lab/Dockerfile directly and
    rebuild vuln-lab-image:latest with fewer CVEs each successful run. Subsequent
    runs find a smaller CVE pool because the "easy" vulns are already patched
    into the image.

    For fair back-to-back trivy-image-ec2 demo runs we need:
      1. Original Dockerfile restored (with intentional vulnerable pins)
      2. All .bak-* Dockerfile copies cleaned up
      3. vuln-lab-image:latest rebuilt from the pristine Dockerfile
      4. Pre-fix backup image tags removed (docker leaves vuln-lab-image:pre-fix-*
         behind after each fix run's backup step)

    Sibling of reset_appsec_lab.py — same shape, different lab.

Transport safety:
    Dockerfile content is base64-encoded before going through SSM to avoid ANY
    shell parsing of the contents (heredocs, quotes, $variables all pass through
    cleanly).

    Docker build happens ON env2 via SSM — this script never rebuilds locally.
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

import boto3
from dotenv import load_dotenv


# =============================================================================
# The pristine Dockerfile — intentionally outdated ubuntu:20.04 base with a
# pinned vulnerable openssl. Embedded here (not in the repo's infra/ tree)
# because this file IS the source of truth for what "pristine" means for
# vuln-lab-image. Committed here so the reset is reproducible across machines.
# =============================================================================
_PRISTINE_DOCKERFILE = """# Intentionally outdated base image with known CVEs
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \\
    openssl=1.1.1f-1ubuntu2 \\
    curl \\
    wget \\
    nginx \\
    && rm -rf /var/lib/apt/lists/*

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
# VULN: Using ADD instead of COPY for local files
ADD app.py /app/app.py

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
"""

_ENV2_DOCKERFILE_PATH = "/opt/vuln-labs/infra-lab/Dockerfile"
_ENV2_BUILD_DIR = "/opt/vuln-labs/infra-lab"
_IMAGE_NAME = "vuln-lab-image:latest"


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
        if inv.get("Status") in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    if inv is None:
        return -1, "", f"poll never succeeded (last error: {last_poll_err})"
    rc_val = inv.get("ResponseCode")
    rc = int(rc_val) if rc_val is not None else -1
    return rc, inv.get("StandardOutputContent", ""), inv.get("StandardErrorContent", "")


def _upload_dockerfile(client, instance_id: str, dockerfile: str) -> tuple[bool, str]:
    """Base64-upload dockerfile bytes and write to _ENV2_DOCKERFILE_PATH.
    Returns (success, message)."""
    b64 = base64.b64encode(dockerfile.encode("utf-8")).decode("ascii")
    # Use printf + base64 -d to write. mkdir -p ensures the target dir exists.
    cmd = (
        f"mkdir -p '{_ENV2_BUILD_DIR}' && "
        f"printf '%s' '{b64}' | base64 -d > '{_ENV2_DOCKERFILE_PATH}' && "
        f"echo WROTE_$(wc -c < '{_ENV2_DOCKERFILE_PATH}')_BYTES"
    )
    rc, out, err = _ssm_run(client, instance_id, cmd, timeout_s=30)
    if rc != 0:
        return False, f"rc={rc} stderr={err[:200]}"
    return True, out.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without executing",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Only restore Dockerfile + cleanup, skip docker build (faster iteration)",
    )
    parser.add_argument(
        "--instance-id",
        default=None,
        help="Target EC2 instance id. Defaults to FIXER_ENV2_INSTANCE_ID from .env",
    )
    args = parser.parse_args()

    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)
    import os

    instance_id = args.instance_id or os.environ.get("FIXER_ENV2_INSTANCE_ID", "")
    if not instance_id:
        print("ERROR: no instance id — set FIXER_ENV2_INSTANCE_ID in .env or pass --instance-id")
        return 2

    print(f"Target env2 instance: {instance_id}")
    print(f"Dockerfile target:    {_ENV2_DOCKERFILE_PATH}")
    print(f"Image to rebuild:     {_IMAGE_NAME}")
    print(f"Dockerfile bytes:     {len(_PRISTINE_DOCKERFILE)}")
    print(f"Skip build:           {args.skip_build}")

    if args.dry_run:
        print("\n(--dry-run — no changes made)")
        print("\nWould execute:")
        print("  1. Upload pristine Dockerfile (base64 via SSM)")
        print("  2. rm -f /opt/vuln-labs/infra-lab/Dockerfile.bak-*")
        if not args.skip_build:
            print(
                "  3. cd /opt/vuln-labs/infra-lab && docker build --no-cache -t vuln-lab-image:latest ."
            )
            print("  4. Remove docker images matching 'vuln-lab-image:pre-fix-*'")
            print("  5. Verify openssl pin via docker run")
        return 0

    client = boto3.client(
        "ssm",
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )

    # 1. Upload pristine Dockerfile
    print("\n[1/5] Uploading pristine Dockerfile...")
    ok, msg = _upload_dockerfile(client, instance_id, _PRISTINE_DOCKERFILE)
    if not ok:
        print(f"  ✗ FAILED: {msg}")
        return 1
    print(f"  ✓ {msg}")

    # 2. Clean up .bak-* files from prior fix runs
    print("\n[2/5] Cleaning up Dockerfile.bak-* files...")
    rc, out, err = _ssm_run(
        client,
        instance_id,
        f"ls '{_ENV2_BUILD_DIR}'/Dockerfile.bak-* 2>/dev/null | wc -l && "
        f"rm -f '{_ENV2_BUILD_DIR}'/Dockerfile.bak-* && echo CLEANED",
        timeout_s=30,
    )
    bak_count = out.strip().split("\n")[0] if out else "0"
    print(f"  ✓ Removed {bak_count} .bak-* file(s)")

    if args.skip_build:
        print("\n(--skip-build — leaving image as-is)")
        return 0

    # 3. Rebuild vuln-lab-image:latest from pristine Dockerfile
    print("\n[3/5] Rebuilding vuln-lab-image:latest --no-cache (this takes ~60-120s)...")
    rc, out, err = _ssm_run(
        client,
        instance_id,
        f"cd '{_ENV2_BUILD_DIR}' && docker build --no-cache -t {_IMAGE_NAME} . 2>&1 | tail -20",
        timeout_s=300,
    )
    if rc != 0:
        print(f"  ✗ docker build failed (rc={rc}):")
        print(f"    stdout: {out[-500:]}")
        print(f"    stderr: {err[-500:]}")
        return 1
    print("  ✓ docker build succeeded")
    print(f"    last lines: {(out or '').strip().splitlines()[-3:]}")

    # 4. Remove pre-fix backup image tags left by prior fix runs
    print("\n[4/5] Removing pre-fix backup image tags...")
    rc, out, err = _ssm_run(
        client,
        instance_id,
        "docker images --format '{{.Repository}}:{{.Tag}}' | grep 'pre-fix' | "
        "xargs -r docker rmi 2>&1 | tail -5 || true",
        timeout_s=60,
    )
    print(f"  ✓ Cleanup: {(out or 'no pre-fix tags found').strip()[:200]}")

    # 5. Verify openssl pin — should show 1.1.1f-1ubuntu2 (the vulnerable pin)
    print("\n[5/5] Verifying openssl version in rebuilt image...")
    rc, out, err = _ssm_run(
        client,
        instance_id,
        f"docker run --rm {_IMAGE_NAME} dpkg -l openssl 2>&1 | grep openssl | tail -3",
        timeout_s=60,
    )
    if rc != 0:
        print(f"  ⚠ Verification failed (rc={rc}) — image may not be functional")
        print(f"    stderr: {err[:200]}")
        return 1
    print("  ✓ openssl in image:")
    for line in (out or "").strip().split("\n"):
        print(f"      {line}")
    if "1.1.1f-1ubuntu2" in (out or ""):
        print("\n  ✓✓ Pristine vulnerable pin confirmed (1.1.1f-1ubuntu2)")
    else:
        print("\n  ⚠ openssl version doesn't match expected pin — check output above")

    print("\n✓ Reset complete. Ready for a fresh trivy-image-ec2 demo run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
