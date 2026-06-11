# Runbook: Sync Lambda Failure

## Trigger

- CloudWatch alarm: `sisyfix-{env}-nvd-sync-errors` fires (Lambda errors > 0 for 2 consecutive periods)
- DLQ alarm: `sisyfix-{env}-nvd-sync-dlq` fires (messages visible > 0)
- SNS notification received by on-call

## Diagnosis

### 1. Check CloudWatch Logs

```bash
# View recent Lambda logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/sisyfix-{env}-nvd-sync" \
  --start-time $(date -d '1 hour ago' +%s000) \
  --filter-pattern "ERROR"
```

Look for the `SYNC_FAILED` log event. The structured JSON log includes:
- `sync_mode`: which path failed (normal, gap_recovery, critical)
- `error`: the exception message
- `items_written`: how far it got before failure

### 2. Check DLQ Messages

```bash
# Peek at DLQ messages
aws sqs receive-message \
  --queue-url https://sqs.{region}.amazonaws.com/{account}/sisyfix-{env}-nvd-sync-dlq \
  --max-number-of-messages 5
```

DLQ messages contain the original EventBridge event that failed. The `detail` field is typically empty (scheduled events), so focus on the Lambda error logs.

### 3. Common Failure Causes

| Log Message | Cause | Resolution |
|-------------|-------|------------|
| `Failed to fetch META file` | NVD endpoint down or network issue | Wait; will auto-recover on next run |
| `Failed to download feed` | NVD feed URL unreachable | Check NVD status page; wait |
| `Exhausted 3 retries with N unprocessed items` | DynamoDB throttling or timeout | Check DynamoDB metrics; may need to wait for capacity |
| `Timeout safety triggered` | Lambda ran out of time | Feed too large or DynamoDB slow; will resume from checkpoint |
| `Gap exceeds 120 days` | Critical gap — manual backfill needed | See [backfill runbook](./backfill.md) |
| `Failed to retrieve NVD API key from SSM` | SSM permission or parameter missing | Check IAM + SSM parameter exists |

## Resolution Steps

### Transient failures (network, throttling)

**No action needed.** The system is designed to self-heal:
- Checkpoint is unchanged on failure
- Next scheduled run reprocesses from the same point
- EventBridge retries up to 2 times before sending to DLQ

### Persistent failures (>3 consecutive runs failing)

1. Check NVD status: https://nvd.nist.gov/
2. Check DynamoDB metrics (throttling, latency) in CloudWatch
3. Check Lambda metrics (duration, memory usage)
4. If DynamoDB is degraded: wait for AWS to resolve
5. If NVD is down: wait; no data loss due to checkpoint design

### Critical gap alert

See [Gap Recovery runbook](./gap-recovery.md).

## Verification

After the issue resolves, confirm recovery:

```bash
# Check latest successful sync
aws dynamodb get-item \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --key '{"pk": {"S": "SYSTEM#SYNC"}, "sk": {"S": "NVD"}}' \
  --query 'Item.last_successful_sync.S'
```

The `last_successful_sync` timestamp should be within the last scheduled interval (2h prod, 6h dev).

## Escalation

- If failures persist >24 hours: investigate AWS service health dashboard
- If DLQ depth >10: consider manual invocation to clear backlog
- If critical gap detected: follow backfill procedure
