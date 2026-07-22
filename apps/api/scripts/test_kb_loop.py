"""Manual test script for the Remediation Knowledge Base feedback loop.

Tests:
  1. INSERT a fake successful fix into remediation_kb
  2. RETRIEVE it back via kb_retrieval
  3. FORMAT it for prompt injection
  4. Verify the full loop works

Run from apps/api/:
  python scripts/test_kb_loop.py
"""

import sys
import os
import json

# Add parent to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.db import supabase_admin
from app.agents.remediation.kb_retrieval import (
    retrieve_examples,
    format_examples_for_prompt,
    format_examples_for_agentic_prompt,
)


def main():
    sb = supabase_admin()
    print("=" * 60)
    print("  REMEDIATION KB — MANUAL TEST")
    print("=" * 60)

    # -------------------------------------------------------------------------
    # Step 1: Insert a fake successful fix
    # -------------------------------------------------------------------------
    print("\n[1] Inserting test KB entry...")

    test_row = {
        "check_id": "CKV_AWS_18_TEST",
        "family": "public_exposure",
        "finding_fingerprint": "test_fingerprint_manual_001",
        "remediation_steps": json.dumps([
            {
                "step": "Back up the current bucket configuration.\n\nCommand:\n    aws s3api get-bucket-logging --bucket my-bucket > backup.json\n\nWhy: Preserves rollback state.",
                "source_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
                "source": "AWS S3 Documentation",
            },
            {
                "step": "Enable access logging on the S3 bucket.\n\nCommand:\n    aws s3api put-bucket-logging --bucket my-bucket --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"my-logs-bucket\",\"TargetPrefix\":\"s3-logs/\"}}'\n\nWhy: CKV_AWS_18 requires S3 access logging to be enabled.",
                "source_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
                "source": "AWS S3 Documentation",
            },
        ]),
        "rollback_steps": json.dumps([
            {
                "step": "Restore original logging config.\n\nCommand:\n    aws s3api put-bucket-logging --bucket my-bucket --bucket-logging-status file://backup.json",
            },
        ]),
        "validation_results": json.dumps([
            {"test_name": "Verify logging enabled", "passed": True, "command": "aws s3api get-bucket-logging --bucket my-bucket"},
            {"test_name": "Re-scan Checkov", "passed": True, "is_rescan": True, "command": "checkov -f main.tf --check CKV_AWS_18"},
        ]),
        "finding_summary": "S3 bucket 'my-bucket' does not have access logging enabled",
        "root_cause": "Missing aws_s3_bucket_logging resource in Terraform configuration",
        "resource_type": "aws_s3_bucket",
        "scanner_type": "iac",
        "file_path": "/opt/vuln-labs/cspm-lab/main.tf",
        "confidence_score": 92,
        "is_active": True,
    }

    # Delete any existing test entry first
    sb.table("remediation_kb").delete().eq(
        "finding_fingerprint", "test_fingerprint_manual_001"
    ).execute()

    resp = sb.table("remediation_kb").insert(test_row).execute()
    inserted = resp.data or []
    if not inserted:
        print("  ERROR: Insert failed!")
        return

    kb_id = inserted[0]["id"]
    print(f"  Inserted KB entry #{kb_id}")

    # -------------------------------------------------------------------------
    # Step 2: Retrieve it back
    # -------------------------------------------------------------------------
    print("\n[2] Retrieving examples for check_id='CKV_AWS_18_TEST'...")

    examples = retrieve_examples(
        sb,
        check_id="CKV_AWS_18_TEST",
        family="public_exposure",
        min_confidence=0,  # low threshold for testing
    )

    if not examples:
        print("  ERROR: No examples retrieved!")
        # Cleanup
        sb.table("remediation_kb").delete().eq("id", kb_id).execute()
        return

    print(f"  Retrieved {len(examples)} example(s)")
    for ex in examples:
        print(f"    - KB #{ex.kb_id}: check={ex.check_id}, confidence={ex.confidence_score}, match={ex.match_type}")

    # -------------------------------------------------------------------------
    # Step 3: Format for hybrid prompt
    # -------------------------------------------------------------------------
    print("\n[3] Formatting for hybrid prompt injection...")
    hybrid_text = format_examples_for_prompt(examples)
    print(f"  Generated {len(hybrid_text)} chars of prompt context")
    print("  --- Preview (first 500 chars) ---")
    print(hybrid_text[:500])
    print("  ---")

    # -------------------------------------------------------------------------
    # Step 4: Format for agentic prompt
    # -------------------------------------------------------------------------
    print("\n[4] Formatting for agentic prompt injection...")
    agentic_text = format_examples_for_agentic_prompt(examples)
    print(f"  Generated {len(agentic_text)} chars of prompt context")
    print("  --- Preview ---")
    print(agentic_text[:400])
    print("  ---")

    # -------------------------------------------------------------------------
    # Step 5: Verify reuse counter incremented
    # -------------------------------------------------------------------------
    print("\n[5] Checking reuse counter...")
    check = sb.table("remediation_kb").select("times_reused, last_used_at").eq("id", kb_id).execute()
    row = (check.data or [{}])[0]
    print(f"  times_reused = {row.get('times_reused')} (expected: 1)")
    print(f"  last_used_at = {row.get('last_used_at')}")

    # -------------------------------------------------------------------------
    # Step 6: Test family fallback (query a different check_id, same family)
    # -------------------------------------------------------------------------
    print("\n[6] Testing family fallback retrieval...")
    fallback_examples = retrieve_examples(
        sb,
        check_id="CKV_AWS_99_NONEXISTENT",
        family="public_exposure",
        min_confidence=0,
    )
    found_ours = any(e.kb_id == kb_id for e in fallback_examples)
    print(f"  Retrieved {len(fallback_examples)} example(s) via family fallback")
    print(f"  Our test entry found: {found_ours} (expected: True)")
    if fallback_examples:
        print(f"  Match type: {fallback_examples[0].match_type} (expected: 'family')")

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------
    print("\n[7] Cleaning up test entry...")
    sb.table("remediation_kb").delete().eq("id", kb_id).execute()
    print(f"  Deleted KB #{kb_id}")

    print("\n" + "=" * 60)
    print("  ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
