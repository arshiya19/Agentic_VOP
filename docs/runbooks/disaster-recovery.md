# Runbook: Disaster Recovery (PITR Restore)

## When to Use

- Data corruption discovered (bad transformer deployed, wrote wrong data)
- Accidental mass deletion of items
- Need to roll back to a known-good state

## Prerequisites

- PITR must be enabled on the table (enabled in prod, disabled in dev)
- Operator must have the `sisyfix-break-glass-operator` IAM role
- MFA is required to assume the break-glass role

## Important: PITR Only Available in Prod

PITR is intentionally disabled in dev to save costs. If dev data is corrupted, re-run the backfill instead.

## Procedure

### 1. Assume the Break-Glass Role

```bash
# Requires MFA token
aws sts assume-role \
  --role-arn arn:aws:iam::{account}:role/sisyfix-break-glass-operator \
  --role-session-name disaster-recovery \
  --serial-number arn:aws:iam::{account}:mfa/{username} \
  --token-code {mfa-code} \
  --duration-seconds 3600
```

Export the returned credentials:
```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

### 2. Choose the Restore Point

Identify when the data was last known-good:

```bash
# Check available restore window
aws dynamodb describe-continuous-backups \
  --table-name sisyfix-prod-vulnerability-intelligence
```

PITR allows restore to any second within the last 35 days.

### 3. Restore to a New Table

PITR restores to a **new table** — it does not overwrite the existing one.

```bash
aws dynamodb restore-table-to-point-in-time \
  --source-table-name sisyfix-prod-vulnerability-intelligence \
  --target-table-name sisyfix-prod-vulnerability-intelligence-restored \
  --restore-date-time "2024-01-15T10:00:00Z"
```

Wait for restore to complete (can take 15–60 minutes depending on table size):

```bash
aws dynamodb describe-table \
  --table-name sisyfix-prod-vulnerability-intelligence-restored \
  --query 'Table.TableStatus'
# Wait until "ACTIVE"
```

### 4. Validate the Restored Table

```bash
# Spot-check a known CVE
aws dynamodb get-item \
  --table-name sisyfix-prod-vulnerability-intelligence-restored \
  --key '{"pk": {"S": "CVE#CVE-2021-44228"}, "sk": {"S": "INTEL"}}'

# Check item count is reasonable
aws dynamodb describe-table \
  --table-name sisyfix-prod-vulnerability-intelligence-restored \
  --query 'Table.ItemCount'
```

### 5. Swap Tables

**Option A: Terraform rename (recommended)**

Update `infra/dynamodb.tf` to point to the restored table name, or rename the restored table:

```bash
# Delete the corrupted table (CAREFUL — this is irreversible)
# First disable deletion protection via Terraform or CLI
aws dynamodb update-table \
  --table-name sisyfix-prod-vulnerability-intelligence \
  --no-deletion-protection-enabled

aws dynamodb delete-table \
  --table-name sisyfix-prod-vulnerability-intelligence

# Wait for deletion, then rename restored table
# Note: DynamoDB doesn't support rename — you need to export/import
# or update all references to point to the new table name
```

**Option B: Update application config**

Temporarily point the Lambda and API service to the restored table by updating the `INTELLIGENCE_TABLE_NAME` environment variable:

```bash
aws lambda update-function-configuration \
  --function-name sisyfix-prod-nvd-sync \
  --environment "Variables={ENVIRONMENT=prod,TABLE_NAME=sisyfix-prod-vulnerability-intelligence-restored}"
```

### 6. Re-sync from Restore Point

After pointing to the restored table, the checkpoint will reflect the restore point's state. The next scheduled sync will pick up from there and bring data current.

### 7. Clean Up

- Delete the old corrupted table (if using Option A)
- Remove the restored table (if using Option B after data is copied)
- Revoke break-glass session (session auto-expires after 1 hour)
- Document the incident

## Post-Recovery Verification

```bash
# Confirm checkpoint is reasonable
aws dynamodb get-item \
  --table-name sisyfix-prod-vulnerability-intelligence \
  --key '{"pk": {"S": "SYSTEM#SYNC"}, "sk": {"S": "NVD"}}' \
  --query 'Item.last_successful_sync.S'

# Confirm next sync succeeds (wait for scheduled run or invoke manually)
aws lambda invoke \
  --function-name sisyfix-prod-nvd-sync \
  --payload '{}' \
  /tmp/sync-result.json

cat /tmp/sync-result.json
# Should show status: "success"
```

## Recovery Time Estimates

| Step | Duration |
|------|----------|
| Assume break-glass role | 1 minute |
| Start PITR restore | 1 minute |
| Wait for restore to complete | 15–60 minutes |
| Validate + swap | 10 minutes |
| Re-sync to current | 5 minutes (normal sync) or 30+ minutes (if gap built up) |
| **Total RTO** | **30–90 minutes** |
