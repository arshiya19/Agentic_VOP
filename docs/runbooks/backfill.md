# Runbook: Historical Backfill

## When to Run

- **Initial setup** — first time deploying the intelligence layer (table is empty)
- **Critical gap recovery** — sync gap exceeds 120 days
- **Data corruption recovery** — after a PITR restore that rolled back data
- **Schema migration** — if transformer logic changes and items need re-processing

## Prerequisites

1. DynamoDB table exists and is accessible
2. IAM role with DynamoDB write permissions for the target environment
3. Network access to NVD feed download URLs (public internet)
4. Python 3.12+ with `boto3` and `urllib3` installed

## Procedure

### Option 1: GitHub Actions (recommended for prod)

1. Navigate to **Actions** → **Backfill** workflow
2. Click **Run workflow**
3. Select branch: `main`
4. Enter environment: `dev` or `prod`
5. Click **Run workflow**

The workflow:
- Validates the environment input
- Assumes the `sisyfix-backfill-{env}` IAM role via OIDC
- Executes the backfill CLI
- Reports success/failure in the workflow run

### Option 2: Local execution

```bash
# Set up AWS credentials for the target environment
export AWS_PROFILE=sisyfix-dev  # or configure credentials directly
export ENVIRONMENT=dev

# From repo root
cd lambdas
python -m lambdas.nvd_sync.backfill --env dev
```

### Option 3: From an EC2 instance (for large backfills)

For prod backfill where you want a stable long-running connection:

```bash
# SSH to an instance with the backfill IAM role attached
ssh ec2-user@backfill-host

# Clone and run
git clone <repo-url>
cd Agentic_VOP/lambdas
pip install -r requirements.txt
ENVIRONMENT=prod python -m lambdas.nvd_sync.backfill --env prod
```

## What the Backfill Does

1. Reads backfill checkpoint (`pk=SYSTEM#BACKFILL, sk=NVD`) to check progress
2. Downloads NVD yearly feed files (2016–2026) sequentially
3. Decompresses each feed in memory (streaming)
4. Transforms every CVE using the same transformer as the Sync Lambda
5. Writes items in batches of 25 with retry logic
6. Updates backfill checkpoint after each year completes
7. On final completion: sets the sync checkpoint (`pk=SYSTEM#SYNC, sk=NVD`) so normal sync can continue

## Resume Behavior

The backfill is **resumable**:
- If it fails on year 2020, the checkpoint records 2019 as the last completed year
- Re-running the backfill skips 2016–2019 and resumes from 2020
- Items already written are safely overwritten (PutItem upsert — idempotent)

## Error Handling

| Error | Behavior | Action |
|-------|----------|--------|
| Malformed CVE in feed | Skip item, log warning, continue | No action needed — rare and harmless |
| Download failure (1 year) | Retry 3x, then abort | Re-run; will resume from last completed year |
| DynamoDB write failure | Retry 3x, then abort | Check DynamoDB metrics, then re-run |
| All years complete | Set sync checkpoint, exit 0 | Normal sync takes over automatically |

## Monitoring During Backfill

```bash
# Check progress (which year last completed)
aws dynamodb get-item \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --key '{"pk": {"S": "SYSTEM#BACKFILL"}, "sk": {"S": "NVD"}}'

# Count total items in table
aws dynamodb describe-table \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --query 'Table.ItemCount'
```

Expected item count after full backfill: ~250,000 CVE items + system items.

## Duration Estimates

| Environment | Expected Duration | Notes |
|-------------|-------------------|-------|
| Dev | 30–60 minutes | PAY_PER_REQUEST handles burst |
| Prod | 30–60 minutes | Same; DynamoDB on-demand scales automatically |

Duration varies based on NVD feed server response times and DynamoDB write latency.

## Verification

After backfill completes:

```bash
# 1. Check sync checkpoint was set
aws dynamodb get-item \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --key '{"pk": {"S": "SYSTEM#SYNC"}, "sk": {"S": "NVD"}}' \
  --query 'Item.last_successful_sync.S'

# 2. Spot-check a known CVE
aws dynamodb get-item \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --key '{"pk": {"S": "CVE#CVE-2021-44228"}, "sk": {"S": "INTEL"}}' \
  --query 'Item.cve_id.S'
# Should return "CVE-2021-44228" (Log4Shell)

# 3. Verify item count is reasonable
aws dynamodb describe-table \
  --table-name sisyfix-{env}-vulnerability-intelligence \
  --query 'Table.ItemCount'
# Should be >200,000
```
