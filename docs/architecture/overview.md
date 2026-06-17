# Architecture Overview

## System Context

The Vulnerability Intelligence Layer sits between the external NVD data source and the Sisyfix enrichment pipeline. It eliminates direct API calls to NVD during vulnerability scanning by maintaining a local DynamoDB copy of intelligence data.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AWS Account                                     │
│                                                                         │
│  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────────┐  │
│  │ EventBridge  │───▶│   Sync Lambda    │───▶│  DynamoDB             │  │
│  │ (scheduled)  │    │  (nvd-sync)      │    │  Intelligence_Table   │  │
│  └──────────────┘    └────────┬─────────┘    └───────────┬───────────┘  │
│         │                     │                          │              │
│         │ on failure          │ fetches                   │ reads        │
│         ▼                     ▼                          ▼              │
│  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────────┐  │
│  │  SQS DLQ     │    │  NVD Feeds/API   │    │  FastAPI Backend      │  │
│  └──────────────┘    │  (external)      │    │  Intelligence Service │  │
│                      └──────────────────┘    └───────────────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Monitoring: CloudWatch Alarms → SNS → Email                     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Subsystems

### 1. Infrastructure (Terraform)

All AWS resources are provisioned via Terraform with separate state per environment (dev/prod). Resources include:

- **DynamoDB Intelligence_Table** — single-table design with `pk`/`sk` composite key
- **Sync Lambda** — 300s timeout, 512MB memory (prod), reserved concurrency 1
- **EventBridge Rule** — triggers sync every 2h (prod) or 6h (dev)
- **SQS Dead Letter Queue** — captures failed Lambda invocations
- **IAM Roles** — least-privilege, per-concern, environment-isolated
- **CloudWatch Alarms** — Lambda errors, DLQ depth, gap hours, duration
- **SNS Topic** — alert notifications
- **S3 Bucket** — Lambda deployment artifacts
- **SSM Parameter** — NVD API key (encrypted)
- **GitHub OIDC Provider** — keyless CI/CD authentication

### 2. Sync Lambda (`lambdas/nvd_sync/`)

Periodic ingestion of NVD modified feed data. Runs on a schedule and:

1. Reads checkpoint from DynamoDB (last successful sync timestamp + META hash)
2. Determines sync mode based on gap duration (normal / gap recovery / critical)
3. Normal path: fetch META → compare hash → download feed → filter → transform → batch write → update checkpoint
4. Gap recovery path: paginate NVD API for missed CVEs
5. Returns structured `SyncResponse` on every path

### 3. Backfill CLI (`lambdas/nvd_sync/backfill.py`)

One-time historical bulk load of NVD yearly feeds (2016–2026). Processes each year sequentially with checkpoint tracking for resume-on-failure.

### 4. Intelligence Service (`apps/api/app/services/vuln_intelligence.py`)

Read-only Python service class integrated into the FastAPI backend. Provides:

- `get_cve_intelligence(cve_id)` — single CVE lookup
- `batch_get_cve_intelligence(cve_ids)` — batch up to 100 CVEs
- `get_mitre_for_cwes(cwe_ids)` — CWE-to-MITRE mapping lookup

Behind a feature flag (`intelligence_enabled`) for gradual rollout.

### 5. CI/CD Pipelines (`.github/workflows/`)

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `infra-plan.yml` | PR modifying `infra/` | Terraform fmt, validate, Checkov, plan |
| `infra-deploy.yml` | Merge to main modifying `infra/` | Apply to dev (auto), prod (manual approval) |
| `lambda-deploy.yml` | PR/merge modifying `lambdas/` | Lint + test on PR; package + deploy on merge |
| `backfill.yml` | Manual dispatch | Run backfill CLI against specified environment |
| `drift-detection.yml` | Weekly (Monday 6 AM UTC) | Detect infrastructure drift |

## Design Principles

- **Checkpoint-based idempotency** — any failure leaves the system in a re-processable state
- **Source-agnostic framework** — adding EPSS/KEV/MITRE requires only a new transformer + config
- **Environment isolation** — separate Terraform state, IAM deny policies, no cross-env access
- **Graceful degradation** — DynamoDB failures return `lookup_failed`, never crash the caller
- **No static credentials** — GitHub OIDC for CI/CD, SSM for runtime secrets

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Storage | DynamoDB (PAY_PER_REQUEST, single-table) |
| Compute | AWS Lambda (Python 3.12) |
| Scheduling | EventBridge |
| Dead letters | SQS |
| Monitoring | CloudWatch + SNS |
| IaC | Terraform |
| CI/CD | GitHub Actions + OIDC |
| Backend | FastAPI (Python) |
| Testing | pytest, moto, Hypothesis (PBT) |
