# NVD Intelligence Layer — Documentation

This directory contains all documentation for the Vulnerability Intelligence Layer, a DynamoDB-backed local repository that replaces direct NVD API calls with sub-200ms local lookups.

## Contents

| Directory | Purpose | Audience |
|-----------|---------|----------|
| [architecture/](./architecture/) | System diagrams, data flow, component relationships | Engineers onboarding, design reviewers |
| [decisions/](./decisions/) | Architecture Decision Records (ADRs) | Anyone asking "why was this built this way?" |
| [runbooks/](./runbooks/) | Operational procedures for day-2 operations | On-call engineers, platform operators |
| [setup/](./setup/) | First-time setup and bootstrap instructions | New contributors, environment provisioning |

## Quick Links

- **What is this system?** → [Architecture Overview](./architecture/overview.md)
- **How does data flow through?** → [Data Flow](./architecture/data-flow.md)
- **How do I set this up from scratch?** → [Bootstrap Guide](./setup/bootstrap.md)
- **The sync Lambda failed — now what?** → [Sync Failure Runbook](./runbooks/sync-failure.md)
- **Why DynamoDB and not PostgreSQL?** → [ADR-001](./decisions/001-dynamodb-over-rds.md)

## Related Code

| Component | Location | Description |
|-----------|----------|-------------|
| Shared Framework | `lambdas/shared/` | Feed ingestion, DynamoDB writer, checkpoint, logger, exceptions |
| Sync Lambda | `lambdas/nvd_sync/` | NVD feed sync handler, transformer, gap recovery, backfill CLI |
| Intelligence Service | `apps/api/app/services/vuln_intelligence.py` | Read-only DynamoDB lookup service |
| Terraform Infrastructure | `infra/` | DynamoDB, Lambda, EventBridge, IAM, monitoring |
| CI/CD Pipelines | `.github/workflows/` | Infra plan/deploy, Lambda deploy, backfill, drift detection |
