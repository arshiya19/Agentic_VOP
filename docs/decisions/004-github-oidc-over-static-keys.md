# ADR-004: GitHub OIDC Over Static AWS Credentials

**Status:** Accepted  
**Date:** 2024-01  
**Deciders:** Platform team, Security

## Context

CI/CD pipelines need to authenticate to AWS for:
- Terraform plan/apply (infrastructure changes)
- Lambda deployment (package upload to S3, function update)
- Backfill execution (DynamoDB writes)

Options:
1. **Static IAM access keys** stored in GitHub Secrets
2. **GitHub OIDC federation** — short-lived tokens via IAM role assumption

## Decision

Use **GitHub OIDC federation** exclusively for all CI/CD AWS authentication. No static credentials stored in GitHub.

## Rationale

- **No credential rotation** — OIDC tokens are short-lived (15 minutes max), automatically expired
- **No secrets to leak** — nothing stored in GitHub Secrets that can be extracted
- **Fine-grained trust** — IAM trust policies can restrict by exact repository, branch, and environment
- **Audit trail** — CloudTrail shows which workflow/run assumed which role
- **Industry best practice** — AWS and GitHub both recommend OIDC over static keys for Actions

## Implementation

```
GitHub Actions workflow
    │ requests OIDC token
    ▼
GitHub OIDC Provider (token.actions.githubusercontent.com)
    │ issues JWT
    ▼
AWS IAM (sts:AssumeRoleWithWebIdentity)
    │ validates JWT claims
    │ checks trust policy (repo, branch, environment)
    ▼
Temporary credentials (15-minute session)
```

**Trust policy restrictions:**
- Plan role: any branch (read-only operations)
- Apply/deploy roles: `main` branch only
- All roles: exact repo match (`repo:org/repo:*`)
- Session duration: 900 seconds max

## Consequences

**Positive:**
- Zero static credentials in GitHub — nothing to rotate, nothing to leak
- Branch-restricted deployment — only `main` can apply infrastructure or deploy
- Automatic credential expiration — no long-lived keys sitting in config
- Simpler security audits — no credential inventory to maintain

**Negative:**
- First-time bootstrap requires local credentials (chicken-and-egg: OIDC provider must be created first)
- More complex IAM configuration (OIDC provider resource, trust policies with condition keys)
- Debugging auth failures requires understanding JWT claims and trust policy matching

**Operational notes:**
- If the GitHub OIDC thumbprint changes, the IAM provider needs updating (rare, GitHub communicates in advance)
- Trust policy uses `StringEquals` on `sub` claim for branch matching — no wildcards in deployment roles
