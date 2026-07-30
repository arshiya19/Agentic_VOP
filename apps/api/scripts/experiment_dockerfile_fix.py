"""Experiment: Give gpt-4o the Dockerfile + a CVE and see what it produces.

No pipeline code touched. Run standalone:
  cd apps/api
  uv run python scripts/experiment_dockerfile_fix.py

What this does:
  1. SSM → cat the Dockerfile from env2
  2. Constructs a minimal prompt with the Dockerfile + CVE info
  3. Calls gpt-4o directly (no tools, no framework)
  4. Prints the raw LLM response

Goal: see if the LLM can figure out the right fix pattern (remove pin vs
add upgrade line) WITHOUT us telling it which pattern to use.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3
from app.config import settings


def fetch_dockerfile_from_env2() -> str:
    """Read the Dockerfile from env2 via SSM."""
    import time

    instance_id = settings.fixer_env2_instance_id
    if not instance_id:
        print("ERROR: fixer_env2_instance_id not set in .env")
        sys.exit(1)

    ssm = boto3.client("ssm", region_name="us-east-1")
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["cat /opt/vuln-labs/infra-lab/Dockerfile"]},
        TimeoutSeconds=30,
    )
    cmd_id = resp["Command"]["CommandId"]

    # Poll
    for _ in range(15):
        time.sleep(2)
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            break

    if inv["Status"] != "Success":
        print(f"ERROR: SSM returned {inv['Status']}")
        sys.exit(1)

    return inv.get("StandardOutputContent") or ""


def call_llm(dockerfile_content: str, cve_info: dict) -> str:
    """Single gpt-4o call — no tools, no framework."""
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage

    llm = ChatOpenAI(
        model="gpt-4o",
        temperature=0.1,
        max_tokens=3000,
        api_key=settings.openai_api_key,
    )

    system = """You are a container security engineer. Given a Dockerfile and a CVE finding,
produce the exact shell commands needed to fix the CVE in the image.

Rules:
- Your fix MUST edit the Dockerfile (not the running container or host)
- After your edit, `docker build` must succeed
- After rebuild, `trivy image <image>` must no longer report this specific CVE
- Emit ONLY the shell commands (one per line), no explanation
- The Dockerfile is at: /opt/vuln-labs/infra-lab/Dockerfile
- The image rebuilds as: vuln-lab-image:latest
- Build directory: /opt/vuln-labs/infra-lab

Common patterns (choose whichever fits):
- If package is version-pinned in Dockerfile: remove/update the pin with sed
- If package comes from base image (not pinned): add a RUN apt-get upgrade line
- If base image itself is outdated: change the FROM line

Output format — just the commands, nothing else:
  <command 1>
  <command 2>
  ...
"""

    user = f"""DOCKERFILE CONTENT:
```
{dockerfile_content}
```

CVE FINDING:
{json.dumps(cve_info, indent=2)}

Produce the fix commands:"""

    response = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return response.content


def main():
    print("=" * 60)
    print("  EXPERIMENT: Let gpt-4o reason about Dockerfile + CVE")
    print("=" * 60)

    # 1. Fetch Dockerfile
    print("\n[1] Fetching Dockerfile from env2...")
    dockerfile = fetch_dockerfile_from_env2()
    print(f"    Got {len(dockerfile)} chars")
    print(f"    First 3 lines: {dockerfile.splitlines()[:3]}")

    # 2. Simulate a libc-bin CVE finding (the unfixed one)
    cve_info = {
        "cve_id": "CVE-2025-4802",
        "package": "libc-bin",
        "installed_version": "2.31-0ubuntu9.9",
        "fixed_version": "2.31-0ubuntu9.16",
        "severity": "HIGH",
        "title": "libc-bin: buffer overflow in __libc_res_nquery",
        "source": "trivy-image-ec2",
    }

    print(f"\n[2] CVE: {cve_info['cve_id']} ({cve_info['package']})")
    print(f"    Installed: {cve_info['installed_version']}")
    print(f"    Fixed:     {cve_info['fixed_version']}")

    # 3. Call LLM
    print("\n[3] Calling gpt-4o...")
    response = call_llm(dockerfile, cve_info)

    print("\n[4] LLM RESPONSE:")
    print("-" * 60)
    print(response)
    print("-" * 60)

    # 4. Also try an openssl CVE (the pinned one) for comparison
    print("\n\n[5] Now trying an openssl CVE (pinned package) for comparison...")
    openssl_cve = {
        "cve_id": "CVE-2021-3711",
        "package": "openssl",
        "installed_version": "1.1.1f-1ubuntu2",
        "fixed_version": "1.1.1f-1ubuntu2.8",
        "severity": "HIGH",
        "title": "openssl: SM2 decryption buffer overflow",
        "source": "trivy-image-ec2",
    }
    print(f"    CVE: {openssl_cve['cve_id']} ({openssl_cve['package']})")

    response2 = call_llm(dockerfile, openssl_cve)
    print("\n[6] LLM RESPONSE (openssl):")
    print("-" * 60)
    print(response2)
    print("-" * 60)

    print("\n\nDONE. Compare both responses — does the LLM correctly distinguish")
    print("'remove pin' (openssl) from 'add upgrade line' (libc-bin)?")


if __name__ == "__main__":
    main()
