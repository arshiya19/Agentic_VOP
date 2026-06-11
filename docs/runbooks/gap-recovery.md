# Runbook: Gap Recovery

## Context

The NVD modified feed covers the last 8 days of changes. If the sync Lambda hasn't run successfully for more than 8 days, the feed alone cannot recover the gap. The system has two automatic responses:

- **8–120 day gap**: Automatic gap recovery via NVD API (paginated, rate-limited)
- **>120 day gap**: CRITICAL alert — requires manual intervention

## Trigger: Automatic Gap Recovery (8–120 days)

### What happens automatically

1. Sync Lambda detects gap exceeds 8 days
2. Switches to `gap_recovery` sync mode
3. Reads NVD API key from SSM Parameter Store
4. Queries NVD API with `lastModStartDate` = checkpoint
5. Paginates through all results (2000 per page)
6. Rate-limits to 50 requests per 30-second window
7. Transforms and writes items through normal pipeline
8. Updates checkpoint on success

### When it fails

Gap recovery can fail due to:
- NVD API being down
- SSM parameter read failure (API key missing/inaccessible)
- Lambda timeout (gap too large to process in 5 minutes)
- DynamoDB write failures

**Resolution:** Same as sync failures — the system retries on next scheduled invocation. If the gap continues growing and reaches 120 days, it becomes critical.

### Monitoring

Check the `GapHours` CloudWatch metric. Alarm fires when gap exceeds 24 hours continuously.

```bash
# Check current gap
aws dynamodb get-item \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --key '{"pk": {"S": "SYSTEM#SYNC"}, "sk": {"S": "NVD"}}' \
  --query 'Item.last_successful_sync.S'
```

Calculate gap: `current_time - last_successful_sync`.

## Trigger: Critical Gap (>120 days)

### Symptoms

- CloudWatch alarm for gap hours firing continuously
- Lambda logs show: `"Gap exceeds 120 days. Manual re-backfill required."`
- Sync Lambda exits immediately without processing

### Why 120 days?

At 120+ days, the NVD API would return tens of thousands of CVEs across many pages. Processing this volume in a single 5-minute Lambda invocation is unreliable. The backfill CLI is designed for bulk loads and handles this scenario properly.

### Resolution

Run a full or partial backfill:

```bash
# Option 1: Trigger via GitHub Actions (recommended)
# Go to Actions → Backfill → Run workflow → select environment

# Option 2: Run locally
cd lambdas
python -m lambdas.nvd_sync.backfill --env dev
```

See [Backfill runbook](./backfill.md) for detailed steps.

After backfill completes:
1. The sync checkpoint is updated to the backfill completion time
2. Normal scheduled sync resumes automatically
3. Verify: check that the `SYSTEM#SYNC` item has a recent timestamp

## Prevention

- Ensure EventBridge rule is enabled and Lambda is not throttled
- Monitor the `GapHours` metric — alert early (24h) before it becomes critical
- If you're taking the Lambda offline for maintenance, plan for backfill on return
