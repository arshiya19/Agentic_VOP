# Runbook: Credential Rotation

## NVD API Key Rotation

The NVD API key is stored in SSM Parameter Store at `/sisyfix/{env}/nvd-api-key` and used exclusively by the Sync Lambda during gap recovery.

### When to Rotate

- Scheduled rotation (quarterly recommended)
- Suspected compromise
- Key revoked by NVD
- Personnel change (if key was tied to an individual account)

### Procedure

1. **Obtain a new API key** from NVD:
   - Go to https://nvd.nist.gov/developers/request-an-api-key
   - Submit request with the team email
   - Receive new key via email

2. **Update the SSM parameter**:

```bash
# Update dev
aws ssm put-parameter \
  --name "/sisyfix/dev/nvd-api-key" \
  --value "NEW_API_KEY_HERE" \
  --type SecureString \
  --overwrite

# Update prod
aws ssm put-parameter \
  --name "/sisyfix/prod/nvd-api-key" \
  --value "NEW_API_KEY_HERE" \
  --type SecureString \
  --overwrite
```

3. **Clear the Lambda cache** — the API key is cached in Lambda memory (warm starts). To force a re-read:

```bash
# Option A: Wait for cold start (Lambda recycles automatically after ~15 min idle)
# Option B: Force a new execution environment
aws lambda update-function-configuration \
  --function-name sisyfix-{env}-nvd-sync \
  --environment "Variables={ENVIRONMENT={env},FORCE_REFRESH=$(date +%s)}"
```

4. **Verify** — trigger a manual Lambda invocation and check logs for successful SSM read:

```bash
aws lambda invoke \
  --function-name sisyfix-{env}-nvd-sync \
  --payload '{}' \
  /dev/null
```

### Failure Modes

- If the old key is revoked before the new one is set: gap recovery fails until fixed, normal sync (feed-based) is unaffected
- If SSM update fails: Lambda uses cached old key until next cold start

## IAM Role Credentials

IAM roles used by the system do not have static credentials:
- **Lambda execution role** — automatically managed by AWS
- **GitHub OIDC roles** — short-lived tokens, no rotation needed
- **Break-glass role** — MFA-gated, no static keys

No credential rotation needed for IAM roles.

## Break-Glass MFA

The break-glass operator role requires MFA. If the MFA device is lost:

1. Use AWS root account to reset MFA for the break-glass IAM user
2. Re-register a new MFA device
3. Document the new device serial in the team vault
