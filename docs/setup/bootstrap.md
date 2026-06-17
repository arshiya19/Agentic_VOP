# Bootstrap Guide: First-Time Setup

This guide walks through the complete setup of the NVD Intelligence Layer from scratch.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | >= 1.5 | Infrastructure provisioning |
| AWS CLI | >= 2.x | AWS operations and verification |
| Python | >= 3.12 | Lambda code and backfill CLI |
| Git | any | Source control |
| GitHub CLI (`gh`) | >= 2.x | PR creation (optional) |

You also need:
- AWS account with admin permissions (for initial bootstrap only)
- GitHub repository with Actions enabled
- NVD API key (request at https://nvd.nist.gov/developers/request-an-api-key)

## Step 1: Configure AWS Credentials Locally

For the initial bootstrap, you need local AWS credentials with sufficient permissions to create IAM roles, DynamoDB tables, Lambda functions, and OIDC providers.

```bash
aws configure --profile sisyfix-admin
# Enter: Access Key ID, Secret Key, Region (us-east-1), Output (json)

export AWS_PROFILE=sisyfix-admin
```

## Step 2: Create Terraform Backend (S3 + DynamoDB Lock)

If you don't already have a Terraform state backend:

```bash
# Create state bucket
aws s3 mb s3://sisyfix-terraform-state --region us-east-1
aws s3api put-bucket-versioning \
  --bucket sisyfix-terraform-state \
  --versioning-configuration Status=Enabled

# Create lock table
aws dynamodb create-table \
  --table-name sisyfix-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

## Step 3: Initialize and Apply Terraform (Dev)

```bash
cd infra

# Initialize with dev backend config
terraform init -backend-config=backend/dev.hcl

# Review the plan
terraform plan -var-file=environments/dev.tfvars

# Apply — creates all AWS resources including OIDC provider
terraform apply -var-file=environments/dev.tfvars
```

This creates:
- DynamoDB Intelligence_Table
- Sync Lambda function (placeholder — code deployed later)
- EventBridge schedule rule
- SQS DLQ
- IAM roles (including GitHub OIDC roles)
- CloudWatch alarms + SNS topic
- S3 artifact bucket
- SSM parameter (empty — you'll set the value next)
- GitHub OIDC provider

## Step 4: Store the NVD API Key in SSM

```bash
aws ssm put-parameter \
  --name "/sisyfix/dev/nvd-api-key" \
  --value "YOUR_NVD_API_KEY" \
  --type SecureString \
  --description "NVD API key for gap recovery"
```

## Step 5: Configure GitHub Environments

In your GitHub repository settings:

1. Go to **Settings → Environments**
2. Create environment: **`dev`**
   - No protection rules (auto-deploy)
3. Create environment: **`prod`**
   - Add required reviewers (at least 1 team member)
   - This gates production deployments

No secrets needed — OIDC handles authentication.

## Step 6: Verify GitHub OIDC Connection

Push a branch with a small Terraform change (e.g., add a comment) and open a PR. The `infra-plan` workflow should:
1. Successfully assume the `sisyfix-github-infra-plan` role
2. Run `terraform plan` and post results as a PR comment

If it fails with "Not authorized to perform sts:AssumeRoleWithWebIdentity":
- Verify the OIDC provider thumbprint is correct
- Check the trust policy's `sub` condition matches your repo: `repo:{owner}/{repo}:*`

## Step 7: Deploy Lambda Code

Merge a change touching `lambdas/` to main. The `lambda-deploy` workflow will:
1. Package the Lambda code
2. Upload to S3
3. Deploy to dev automatically

Or deploy manually:

```bash
# Package locally
cd lambdas
mkdir -p /tmp/lambda-build
pip install -r requirements.txt -t /tmp/lambda-build/
cp -r shared nvd_sync /tmp/lambda-build/
cd /tmp/lambda-build && zip -r /tmp/lambda.zip .

# Deploy
aws lambda update-function-code \
  --function-name sisyfix-dev-nvd-sync \
  --zip-file fileb:///tmp/lambda.zip
```

## Step 8: Run Initial Backfill

Load historical NVD data (2016–2026) into the table:

```bash
# Via GitHub Actions (recommended)
# Go to Actions → Backfill → Run workflow → environment: dev

# Or locally
cd lambdas
ENVIRONMENT=dev PYTHONPATH=. python -m lambdas.nvd_sync.backfill --env dev
```

This takes 30–60 minutes. Monitor progress:
```bash
aws dynamodb get-item \
  --table-name sisyfix-dev-vulnerability-intelligence \
  --key '{"pk": {"S": "SYSTEM#BACKFILL"}, "sk": {"S": "NVD"}}'
```

## Step 9: Verify Sync Lambda

Invoke the Lambda manually to confirm it works:

```bash
aws lambda invoke \
  --function-name sisyfix-dev-nvd-sync \
  --payload '{}' \
  /tmp/sync-result.json

cat /tmp/sync-result.json
# Should show: {"status": "success", "sync_mode": "normal", ...}
```

## Step 10: Enable Intelligence Service

Update the API configuration to activate DynamoDB lookups:

```bash
# In apps/api/.env (or environment-specific config)
INTELLIGENCE_ENABLED=true
INTELLIGENCE_TABLE_NAME=sisyfix-dev-vulnerability-intelligence
INTELLIGENCE_AWS_REGION=us-east-1
```

Restart the API service and verify enrichment uses local lookups:
- Check API logs for DynamoDB calls instead of NVD API calls
- Monitor the `CacheMissesLookupFailed` CloudWatch metric

## Step 11: Set Up SNS Notifications

Subscribe your alert email to the SNS topic:

```bash
# Terraform handles this via the alert_email variable
# If you need to add subscribers manually:
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:{account}:sisyfix-dev-nvd-sync-alerts \
  --protocol email \
  --notification-endpoint your-team@example.com
```

Confirm the subscription via the email link.

## Step 12: Repeat for Production

Once dev is validated:

1. Apply Terraform to prod:
   ```bash
   terraform init -backend-config=backend/prod.hcl -reconfigure
   terraform plan -var-file=environments/prod.tfvars
   terraform apply -var-file=environments/prod.tfvars
   ```

2. Store NVD API key for prod:
   ```bash
   aws ssm put-parameter \
     --name "/sisyfix/prod/nvd-api-key" \
     --value "YOUR_NVD_API_KEY" \
     --type SecureString
   ```

3. Run backfill for prod (via GitHub Actions → environment: prod)

4. Enable Intelligence Service in prod config

After this, all subsequent changes flow through CI/CD:
- Infrastructure changes: PR → plan → merge → auto-apply dev → manual approve prod
- Lambda changes: PR → lint+test → merge → deploy dev → manual approve prod

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| OIDC role assumption fails | Check trust policy `sub` condition matches `repo:owner/name:ref:refs/heads/main` |
| Terraform state locked | Run `terraform force-unlock {lock-id}` |
| Lambda deployment fails (no function) | Apply Terraform first to create the function resource |
| Backfill timeout | Increase EC2/local machine timeout; backfill resumes from checkpoint |
| SSM GetParameter access denied | Check Lambda execution role has `ssm:GetParameter` on the specific parameter ARN |
