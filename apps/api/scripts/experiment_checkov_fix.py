"""Experiment: Give gpt-4o the Terraform file + Checkov findings and see what it produces.

No pipeline code touched. Run standalone:
  cd apps/api
  uv run python scripts/experiment_checkov_fix.py

Same idea as experiment_dockerfile_fix.py but for IaC/Checkov findings.
"""

import json
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3
from app.config import settings


def fetch_file_from_env2(path: str) -> str:
    """Read a file from env2 via SSM."""
    instance_id = settings.fixer_env2_instance_id
    if not instance_id:
        print("ERROR: fixer_env2_instance_id not set in .env")
        sys.exit(1)

    ssm = boto3.client("ssm", region_name="us-east-1")
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [f"cat {path}"]},
        TimeoutSeconds=30,
    )
    cmd_id = resp["Command"]["CommandId"]

    for _ in range(15):
        time.sleep(2)
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            break

    if inv["Status"] != "Success":
        print(f"ERROR: SSM returned {inv['Status']}")
        sys.exit(1)

    return inv.get("StandardOutputContent") or ""


def call_llm(file_content: str, file_path: str, finding: dict) -> str:
    """Single gpt-4o call — no tools, no framework."""
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage

    llm = ChatOpenAI(
        model="gpt-4o",
        temperature=0.1,
        max_tokens=3000,
        api_key=settings.openai_api_key,
    )

    system = """You are an infrastructure security engineer. Given a Terraform file and a
Checkov finding, produce the exact shell commands needed to fix the finding.

Rules:
- Your fix MUST edit the Terraform file at the given path
- After your edit, `terraform plan` must succeed (no syntax errors)
- After `terraform apply`, `checkov --check <check_id>` must pass
- Emit ONLY the shell commands (one per line), no explanation
- The working directory is the same as the file's directory
- Available tools: sed, cat (heredoc), terraform, checkov

Output format — just the commands, nothing else:
  <command 1>
  <command 2>
  ...
"""

    user = f"""TERRAFORM FILE ({file_path}):
```
{file_content}
```

CHECKOV FINDING:
{json.dumps(finding, indent=2)}

Produce the fix commands:"""

    response = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return response.content


def main():
    print("=" * 60)
    print("  EXPERIMENT: Let gpt-4o reason about Terraform + Checkov")
    print("=" * 60)

    tf_path = "/opt/vuln-labs/cspm-lab/main.tf"

    # 1. Fetch the Terraform file
    print(f"\n[1] Fetching {tf_path} from env2...")
    tf_content = fetch_file_from_env2(tf_path)
    print(f"    Got {len(tf_content)} chars")
    print(f"    First 3 lines: {tf_content.splitlines()[:3]}")

    # 2. Three different Checkov findings
    findings = [
        {
            "check_id": "CKV_AWS_21",
            "check_name": "Ensure all data stored in the S3 bucket have versioning enabled",
            "resource": "aws_s3_bucket.vulnerable_bucket",
            "severity": "HIGH",
            "guideline": "https://docs.bridgecrew.io/docs/s3_16-enable-versioning",
        },
        {
            "check_id": "CKV_AWS_18",
            "check_name": "Ensure the S3 bucket has access logging enabled",
            "resource": "aws_s3_bucket.vulnerable_bucket",
            "severity": "HIGH",
            "guideline": "https://docs.bridgecrew.io/docs/s3_13-enable-logging",
        },
        {
            "check_id": "CKV_AWS_24",
            "check_name": "Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
            "resource": "aws_security_group.vulnerable_sg",
            "severity": "HIGH",
            "guideline": "https://docs.bridgecrew.io/docs/networking_1-port-security",
        },
    ]

    for i, finding in enumerate(findings, start=1):
        print(f"\n{'='*60}")
        print(f"[{i+1}] Finding: {finding['check_id']} — {finding['check_name']}")
        print(f"    Resource: {finding['resource']}")
        print(f"\n    Calling gpt-4o...")

        response = call_llm(tf_content, tf_path, finding)

        print(f"\n    LLM RESPONSE:")
        print("    " + "-" * 56)
        for line in response.strip().splitlines():
            print(f"    {line}")
        print("    " + "-" * 56)

    print("\n\nDONE. Check if the LLM produced correct fixes for each finding")
    print("without us telling it specific patterns (sed vs cat >> vs etc.)")


if __name__ == "__main__":
    main()
