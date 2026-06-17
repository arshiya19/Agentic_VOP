# Vulnerability Intelligence Layer — Full Requirements Specification

**Version:** 1.0
**Date:** 2025-06-04
**Status:** Approved for Implementation
**Author:** Architecture Planning Session

---

## Table of Contents

1. [Overview](#1-overview)
2. [Repository Structure](#2-repository-structure)
3. [Environments](#3-environments)
4. [DynamoDB Table Design](#4-dynamodb-table-design)
5. [Item Schema](#5-item-schema)
6. [Initial Backfill](#6-initial-backfill)
7. [Ongoing Synchronization](#7-ongoing-synchronization)
8. [Gap Recovery](#8-gap-recovery)
9. [Cache Miss Handling](#9-cache-miss-handling)
10. [Enrichment Service Integration](#10-enrichment-service-integration)
11. [Lambda Architecture](#11-lambda-architecture)
12. [Generic Feed-Ingestion Framework](#12-generic-feed-ingestion-framework)
13. [CI/CD Pipeline](#13-cicd-pipeline)
14. [IAM Policy Design](#14-iam-policy-design)
15. [Monitoring and Alerting](#15-monitoring-and-alerting)
16. [Cost Estimates](#16-cost-estimates)
17. [Rollback Strategy](#17-rollback-strategy)
18. [Future Considerations](#18-future-considerations)

---

## 1. Overview

### 1.1 Purpose

Build a local Vulnerability Intelligence repository stored in AWS DynamoDB to replace direct NVD API calls during enrichment. This provides faster enrichment, eliminates rate-limit concerns, and establishes a foundation for multi-source intelligence (EPSS, KEV, MITRE).

### 1.2 Planned Flow

```
NVD Yearly Feeds → Historical Loader (CLI) → DynamoDB
EventBridge → Lambda Sync (Modified Feed) → DynamoDB
Application → Intelligence Service → DynamoDB (read-only)
Cache Miss: Application receives lookup_failed → self-heals on next sync cycle
```

### 1.3 Key Decisions

- Monorepo approach (infrastructure alongside application)
- Terraform for IaC
- Two environments (dev + prod)
- Single consolidated DynamoDB table
- NVD data feeds (not API) for backfill and ongoing sync
- API is read-only; sync Lambda is the sole authoritative writer
- GitHub OIDC for AWS authentication (no static credentials)

---

## 2. Repository Structure

### 2.1 Directory Tree

```
Agentic_VOP/
├── apps/
│   ├── api/                          # Existing FastAPI backend
│   │   └── app/
│   │       └── services/
│   │           └── vuln_intelligence.py  # New: vulnerability intelligence service (read-only)
│   └── web/                          # Existing React frontend
├── infra/
│   └── terraform/
│       ├── modules/
│       │   ├── dynamodb/
│       │   │   └── main.tf
│       │   ├── lambda/
│       │   │   └── main.tf
│       │   ├── eventbridge/
│       │   │   └── main.tf
│       │   ├── iam/
│       │   │   ├── main.tf
│       │   │   ├── variables.tf
│       │   │   └── outputs.tf
│       │   ├── monitoring/
│       │   │   └── main.tf
│       │   └── sqs/
│       │       └── main.tf
│       ├── environments/
│       │   ├── dev.tfvars
│       │   └── prod.tfvars
│       ├── main.tf
│       ├── variables.tf
│       ├── outputs.tf
│       └── backend.tf
├── lambdas/
│   ├── nvd_sync/
│   │   ├── handler.py
│   │   ├── backfill.py
│   │   ├── transformer.py
│   │   ├── config.py
│   │   ├── requirements.txt
│   │   └── tests/
│   │       ├── test_handler.py
│   │       ├── test_transformer.py
│   │       └── fixtures/
│   └── shared/
│       ├── feed_ingestion.py
│       ├── dynamo_writer.py
│       ├── checkpoint.py
│       ├── exceptions.py
│       └── models.py
├── docs/
│   ├── architecture/
│   │   ├── nvd-intelligence-layer-spec.md  (this file)
│   │   └── diagrams/
│   ├── decisions/
│   │   ├── 001-monorepo-structure.md
│   │   ├── 002-dynamodb-for-nvd.md
│   │   ├── 003-feed-based-sync.md
│   │   └── template.md
│   └── runbooks/
│       ├── nvd-historical-backfill.md
│       ├── lambda-failure-triage.md
│       ├── dynamodb-pitr-recovery.md
│       └── dynamodb-capacity-scaling.md
├── .github/
│   └── workflows/
│       ├── lint.yml              # Existing (extend for lambdas/)
│       ├── security.yml          # Existing (extend for lambdas/)
│       ├── infra.yml             # New
│       ├── lambda-deploy.yml     # New
│       ├── backfill.yml          # New
│       └── drift-detection.yml   # New
└── README.md
```

### 2.2 Rationale

- Single repo enables atomic changes across infrastructure, Lambda, and API
- Path-filtered CI prevents unrelated changes from triggering irrelevant pipelines
- `lambdas/` directory contains both Lambda handlers and CLI scripts (shared codebase)
- `docs/` provides living documentation reviewed alongside code

---

## 3. Environments

### 3.1 Configuration

| Setting | Dev | Prod |
|---|---|---|
| Count | 1 | 1 |
| Differentiation | `environments/dev.tfvars` | `environments/prod.tfvars` |
| State isolation | `key=nvd-intelligence/dev/terraform.tfstate` | `key=nvd-intelligence/prod/terraform.tfstate` |
| Resource naming | `sisyfix-dev-{resource}` | `sisyfix-prod-{resource}` |
| AWS account | Single shared account | Single shared account |
| Sync frequency | `rate(6 hours)` | `rate(2 hours)` |
| Lambda memory | 256 MB | 512 MB |
| Lambda timeout | 300 seconds | 300 seconds |
| DynamoDB PITR | Off | On |
| DynamoDB deletion protection | Off | On |
| TTL (dev cleanup) | Optional 30 days | Off |
| Budget alert threshold | $10 | $25 |

### 3.2 Deployment

```bash
# Dev
terraform init -backend-config="key=nvd-intelligence/dev/terraform.tfstate"
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars

# Prod
terraform init -backend-config="key=nvd-intelligence/prod/terraform.tfstate"
terraform plan -var-file=environments/prod.tfvars
terraform apply -var-file=environments/prod.tfvars
```

---

## 4. DynamoDB Table Design

### 4.1 Table Configuration

| Setting | Value |
|---|---|
| Table name | `sisyfix-{env}-vulnerability-intelligence` |
| Partition key | `pk` (String) |
| Sort key | `sk` (String) |
| Billing mode | PAY_PER_REQUEST (on-demand) |
| Encryption | AWS-managed key |
| PITR | Off (dev), On (prod) |
| Deletion protection | Off (dev), On (prod) |

### 4.2 Key Design

| Item Type | Partition Key (pk) | Sort Key (sk) | Purpose |
|---|---|---|---|
| CVE Intelligence | `CVE#CVE-2025-1234` | `INTEL` | Consolidated NVD + EPSS + KEV data |
| MITRE Mapping | `CWE#CWE-120` | `MITRE` | ATT&CK technique mappings per CWE |
| Sync Checkpoint | `SYSTEM#SYNC` | `NVD` | Sync state tracking |
| Backfill Progress | `SYSTEM#BACKFILL` | `NVD` | Backfill state tracking |
| Negative Cache | `CVE#CVE-2025-GARBAGE` | `INTEL` | CVEs confirmed not to exist in NVD |

### 4.3 Design Rationale

- Sort key enables future item types under same CVE (history, raw source data) without migration
- MITRE is separate item type (CWE-keyed, not CVE-keyed) in same table — different key space, independent sync
- EPSS and KEV are nested in CVE item (1:1 with CVE, always read together)
- Single table reduces operational overhead (one table to monitor, alarm, manage)

### 4.4 Access Patterns

| Pattern | Operation | Key |
|---|---|---|
| Enrich a CVE | GetItem | `pk=CVE#xxx, sk=INTEL` |
| Batch enrich | BatchGetItem | Multiple `pk=CVE#xxx, sk=INTEL` |
| Get MITRE for CWE | GetItem | `pk=CWE#xxx, sk=MITRE` |
| Batch MITRE | BatchGetItem | Multiple `pk=CWE#xxx, sk=MITRE` |
| Read checkpoint | GetItem | `pk=SYSTEM#SYNC, sk=NVD` |
| Write intelligence | PutItem / BatchWriteItem | `pk=CVE#xxx, sk=INTEL` |
| Update checkpoint | UpdateItem | `pk=SYSTEM#SYNC, sk=NVD` |

### 4.5 Future GSIs (Designed, Not Built)

| GSI Name | PK | SK | Use Case |
|---|---|---|---|
| `severity-index` | `nvd.cvss_v31_severity` | `cve_id` | All CRITICAL CVEs |
| `kev-index` | `kev.is_known_exploited` | `kev.due_date` | KEV vulns by deadline |

---

## 5. Item Schema

### 5.1 CVE Intelligence Item

```json
{
  "pk": "CVE#CVE-2025-1234",
  "sk": "INTEL",
  "cve_id": "CVE-2025-1234",
  "resolution": "resolved",
  "nvd": {
    "description": "A buffer overflow in...",
    "cvss_v31_score": 9.8,
    "cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_v31_severity": "CRITICAL",
    "cvss_attack_vector": "NETWORK",
    "cvss_attack_complexity": "LOW",
    "cvss_privileges_required": "NONE",
    "cvss_user_interaction": "NONE",
    "cwe_ids": ["CWE-120"],
    "affected_products": [
      { "vendor": "apache", "product": "http_server", "versions": "< 2.4.58" }
    ],
    "references": ["https://..."],
    "published_date": "2025-01-15T00:00:00Z",
    "last_modified_date": "2025-03-10T00:00:00Z",
    "source_updated_at": "2025-03-10T00:00:00Z"
  },
  "epss": null,
  "kev": null,
  "mitre": null,
  "metadata": {
    "created_at": "2025-06-01T10:00:00Z",
    "updated_at": "2025-06-03T14:30:00Z",
    "sources_present": ["nvd"],
    "version": 1
  }
}
```

### 5.2 EPSS Nested Object (Future)

```json
"epss": {
  "score": 0.94,
  "percentile": 99.2,
  "scored_at": "2025-06-02T00:00:00Z"
}
```

### 5.3 KEV Nested Object (Future)

```json
"kev": {
  "is_known_exploited": true,
  "date_added": "2025-02-10",
  "due_date": "2025-03-03",
  "ransomware_use": "Known",
  "notes": "Apply vendor patch"
}
```

### 5.4 MITRE Mapping Item

```json
{
  "pk": "CWE#CWE-120",
  "sk": "MITRE",
  "cwe_id": "CWE-120",
  "attack_techniques": [
    {
      "technique_id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "Initial Access"
    }
  ],
  "updated_at": "2025-05-01T00:00:00Z"
}
```

### 5.5 Negative Cache Item

```json
{
  "pk": "CVE#CVE-2025-GARBAGE",
  "sk": "INTEL",
  "cve_id": "CVE-2025-GARBAGE",
  "resolution": "not_found",
  "nvd": null,
  "epss": null,
  "kev": null,
  "metadata": {
    "created_at": "2025-06-03T14:00:00Z",
    "updated_at": "2025-06-03T14:00:00Z",
    "sources_present": [],
    "not_found_at": "2025-06-03T14:00:00Z",
    "ttl": 1751760000
  }
}
```

### 5.6 Resolution States

| Resolution | Stored in DynamoDB? | Meaning | Retry? |
|---|---|---|---|
| `resolved` | Yes | Full intelligence data available | No |
| `not_found` | Yes (with TTL) | CVE confirmed not to exist in NVD | After TTL expires (7-30 days) |
| `lookup_failed` | No (in-memory only) | NVD temporarily unavailable | Yes (next sync cycle) |

---

## 6. Initial Backfill

### 6.1 Configuration

| Setting | Value |
|---|---|
| Data source | NVD 2.0 yearly JSON feed files (2016-2026) |
| Execution method | CLI script (`lambdas/nvd_sync/backfill.py`) |
| Invocation | `python -m nvd_sync.backfill --env dev` or GitHub Actions workflow_dispatch |
| Scope | ~200,000 CVEs (2016-present) |
| Download size | ~135 MB compressed |
| Estimated duration | ~10-15 minutes |
| One-time cost | ~$0.31 per environment |
| Idempotency | Safe to re-run (PutItem upsert behavior) |

### 6.2 Process

```
For each year in [2016, 2017, ..., 2026]:
  1. Download nvdcve-2.0-{year}.json.gz from NVD
  2. Decompress in memory (streaming)
  3. Parse JSON → extract CVE items
  4. Transform to DynamoDB item shape
  5. BatchWriteItem (25 items per batch)
  6. Update progress checkpoint
Set initial sync checkpoint = current timestamp
```

### 6.3 Post-Backfill

- Set `SYSTEM#SYNC` checkpoint to backfill completion timestamp
- Next modified feed sync picks up only items modified after backfill
- Zero redundant writes

---

## 7. Ongoing Synchronization

### 7.1 Configuration

| Setting | Value |
|---|---|
| Data source | NVD modified feed (`nvdcve-2.0-modified.json.gz`) + META file |
| Trigger | EventBridge scheduled rule |
| Schedule | `rate(2 hours)` prod, `rate(6 hours)` dev |
| Execution | Lambda function (`sisyfix-{env}-nvd-sync`) |
| Lambda timeout | 300 seconds |
| Lambda memory | 512 MB (prod), 256 MB (dev) |
| Concurrency | Reserved concurrency = 1 |
| Typical duration | 30-45 seconds |
| Items written per run | ~50-100 (only truly new/modified) |

### 7.2 Sync Flow

```
EventBridge → Lambda handler.py
  1. Read checkpoint from DynamoDB (1 read)
  2. Calculate gap = now() - last_successful_sync
  3. Route by gap duration:
     - < 8 days → normal path (modified feed)
     - 8-120 days → gap recovery (NVD API)
     - > 120 days → critical alert, no auto-recovery
  4. Normal path:
     a. Fetch META file → compare SHA256 against stored hash
     b. If unchanged → exit early (no work)
     c. Download modified feed (~2.3 MB)
     d. Decompress + parse
     e. Filter: only CVEs with lastModifiedDate > checkpoint
     f. Transform to DynamoDB item shape
     g. BatchWriteItem (buffered, 25 per batch)
     h. Update checkpoint = max(lastModifiedDate) from written items
  5. Return structured summary
```

### 7.3 Write Optimization

- In-memory timestamp filtering: `CVE.lastModifiedDate > checkpoint`
- No DynamoDB reads for filtering (only 1 read: checkpoint)
- Conditional write safety net: `attribute_not_exists(pk) OR metadata.updated_at < :new_ts`
- Only ~50-100 writes per run (vs 1,500 in feed without filtering)

### 7.4 Checkpoint Management

| Rule | Rationale |
|---|---|
| Checkpoint value = max `lastModifiedDate` from written items | Prevents data loss from timing drift |
| Checkpoint updated only after ALL writes succeed | Crash-safe; incomplete runs are idempotent retries |
| Checkpoint never updated on failure | Next run reprocesses from same point |

---

## 8. Gap Recovery

### 8.1 Strategy

| Gap Duration | Detection | Recovery Action |
|---|---|---|
| < 8 days | `now() - checkpoint < 8 days` | Normal path — modified feed covers it |
| 8-120 days | `now() - checkpoint >= 8 days` | NVD API with `lastModStartDate = checkpoint` |
| > 120 days | `now() - checkpoint >= 120 days` | No auto-recovery — alarm + manual re-backfill |

### 8.2 NVD API Key

- Stored in SSM Parameter Store (SecureString): `/sisyfix/{env}/nvd-api-key`
- Read by Lambda at cold start, cached in-memory
- Required for gap recovery path (rate limit: 50 req/30s with key)
- Free to obtain: https://nvd.nist.gov/developers/request-an-api-key

### 8.3 Monitoring

- CloudWatch alarm if gap exceeds 24 hours (7 days of warning before 8-day cliff)
- Separate alarm thresholds: WARNING at 24h, CRITICAL at 6 days

---

## 9. Cache Miss Handling

### 9.1 Strategy

| Setting | Value |
|---|---|
| API write access | Read-only (no cache-miss writes) |
| Cache miss behavior | Return `lookup_failed`, self-heals on next sync |
| Authoritative writer | Sync Lambda only |
| Future async upgrade | Config flag (`CACHE_MISS_STRATEGY`) exists but set to disabled |

### 9.2 Configuration

```python
# apps/api/app/config.py
max_sync_cache_misses: int = 10       # Environment variable: MAX_SYNC_CACHE_MISSES
intelligence_cache_miss_write: bool = False  # API is read-only
```

### 9.3 Future Enablement (Not Day One)

If cache-miss writes are re-enabled later:
- Use conditional write: `attribute_not_exists(pk)`
- Batch resolved misses via BufferedBatchWriteItem
- Resolve first N (configurable), return `lookup_failed` for remainder
- Best-effort write (never block response on write failure)
- Separate metrics for `not_found` vs `lookup_failed`

---

## 10. Enrichment Service Integration

### 10.1 New File

`apps/api/app/services/vuln_intelligence.py`

### 10.2 Interface

```python
class IntelligenceService:
    async def get_cve_intelligence(self, cve_id: str) -> CveIntelligence | None
    async def batch_get_cve_intelligence(self, cve_ids: list[str]) -> dict[str, CveIntelligence]
    async def get_mitre_for_cwes(self, cwe_ids: list[str]) -> dict[str, MitreMapping]
```

### 10.3 Return Models

```python
@dataclass
class CveIntelligence:
    cve_id: str
    resolution: str  # "resolved" | "not_found" | "lookup_failed"
    nvd: NvdData | None
    epss: EpssData | None
    kev: KevData | None
    sources_present: list[str]

@dataclass
class MitreMapping:
    cwe_id: str
    attack_techniques: list[dict]
```

### 10.4 Sub-Agent 2 Integration

| Current (Before) | Target (After) |
|---|---|
| EPSS API call | DynamoDB read (epss nested in CVE item) |
| NVD per-CVE API call (rate-limited) | DynamoDB BatchGetItem (~5-10ms) |
| CISA KEV catalog download | DynamoDB read (kev nested in CVE item) |
| MITRE Supabase lookup | Keep Supabase (migrate to DynamoDB later) |

### 10.5 Performance Impact

| Metric | Before | After |
|---|---|---|
| 50 CVEs enrichment | 3-30 seconds | ~50-100ms |
| 200 CVEs enrichment | 12-120 seconds | ~100-200ms |
| Rate limit risk | Real concern | Zero |
| External dependency | NVD API uptime | DynamoDB 99.99% SLA |

### 10.6 Migration Strategy

| Phase | Action |
|---|---|
| Phase 1 | Deploy DynamoDB + run backfill. Add IntelligenceService. Feature flag OFF. |
| Phase 2 | Enable for dev. Monitor cache misses, data quality. |
| Phase 3 | Enable for prod. Remove legacy API calls. |
| Phase 4 | Remove legacy code from sub_agent_2. |

### 10.7 New Dependency

Add to `apps/api/pyproject.toml`:
```
boto3>=1.34.0
```

---

## 11. Lambda Architecture

### 11.1 Code Structure

```
lambdas/nvd_sync/
├── handler.py         # Lambda entry point (EventBridge → orchestrator)
├── backfill.py        # CLI entry point (manual trigger)
├── transformer.py     # NVD 2.0 JSON → DynamoDB item shape (pure function)
├── config.py          # Feed URLs, thresholds, env-aware settings
├── requirements.txt   # boto3, urllib3
└── tests/

lambdas/shared/
├── feed_ingestion.py  # Download + decompress + META check
├── dynamo_writer.py   # Source-agnostic BatchWriteItem + UpdateItem
├── checkpoint.py      # Read/write sync state
├── exceptions.py      # Custom exception hierarchy
└── models.py          # Shared data shapes
```

### 11.2 Error Handling

| Layer | Error Type | Action |
|---|---|---|
| Per-item | Malformed CVE in feed | Log WARN, skip item, continue |
| Per-batch | DynamoDB throttle / UnprocessedItems | Retry 3x with exponential backoff |
| Top-level | Feed download failure | Abort, don't update checkpoint, retry next run |
| Top-level | DynamoDB unreachable | Abort, don't update checkpoint, retry next run |
| Top-level | Approaching timeout (<30s remaining) | Stop processing, don't update checkpoint |

### 11.3 Timeout Management

| Setting | Value |
|---|---|
| Lambda timeout | 300 seconds |
| Safety buffer | 30 seconds |
| Stop-processing check | `context.get_remaining_time_in_millis() < 30_000` |
| Typical normal sync | 30-45 seconds |
| Typical gap recovery | 60-180 seconds |

### 11.4 Logging

- Structured JSON via CloudWatch Embedded Metric Format (EMF)
- Levels: INFO (normal ops), WARN (recoverable issues), ERROR (sync failed), CRITICAL (human intervention needed)
- Key events: SYNC_STARTED, META_UNCHANGED, FEED_DOWNLOADED, ITEMS_FILTERED, BATCH_WRITTEN, SYNC_COMPLETED, SYNC_FAILED, GAP_RECOVERY

### 11.5 Return Value

```json
{
  "status": "success|failed",
  "sync_mode": "normal|gap_recovery|critical",
  "items_processed": 1487,
  "items_written": 52,
  "items_skipped": 1435,
  "items_failed": 0,
  "new_checkpoint": "2025-06-03T14:22:00Z",
  "duration_ms": 34200
}
```

---

## 12. Generic Feed-Ingestion Framework

### 12.1 Design

Lightweight shared pipeline. Source-specific transformers per feed.

### 12.2 Shared Components (`lambdas/shared/`)

| Component | Responsibility |
|---|---|
| `feed_ingestion.py` | Download GZ, decompress, parse JSON, fetch META |
| `dynamo_writer.py` | `batch_put_items()` and `batch_update_source()` |
| `checkpoint.py` | Read/write sync state per source |
| `exceptions.py` | `FeedDownloadError`, `TransformError`, `WriteError` |
| `models.py` | Shared data shapes |

### 12.3 Writer Abstraction (Source-Agnostic)

```python
class IntelligenceWriter:
    def batch_put_items(self, items: list[dict]) -> WriteResult
    def batch_update_source(self, updates: list[SourceUpdate]) -> WriteResult

@dataclass
class SourceUpdate:
    pk: str
    sk: str
    source_name: str     # "epss", "kev", "nvd"
    source_data: dict
    source_updated_at: str

@dataclass
class WriteResult:
    written: int
    failed: int
    failed_items: list[str]
```

### 12.4 Adding Future Sources

Each new source adds:
- `lambdas/{source}_sync/handler.py` — EventBridge entry point
- `lambdas/{source}_sync/transformer.py` — source-specific JSON → item shape
- `lambdas/{source}_sync/config.py` — feed URLs, schedule

Reuses all shared infrastructure.

---

## 13. CI/CD Pipeline

### 13.1 Workflows

| Workflow | Trigger | Action |
|---|---|---|
| `lint.yml` (existing, extended) | All pushes/PRs | Ruff for `apps/api/` + `lambdas/`, ESLint for `apps/web/` |
| `security.yml` (existing, extended) | All pushes/PRs | Bandit for `apps/api/` + `lambdas/`, Semgrep, Gitleaks, audits |
| `infra.yml` (new) | `infra/**` changes | Terraform validate + Checkov + plan (PR) / apply (main) |
| `lambda-deploy.yml` (new) | `lambdas/**` changes | Test + package + S3 upload + deploy |
| `backfill.yml` (new) | Manual dispatch only | Run historical backfill for target environment |
| `drift-detection.yml` (new) | Weekly schedule (Monday 6 AM UTC) | Terraform plan, alert on drift |

### 13.2 AWS Authentication

- GitHub OIDC → IAM roles (no static credentials)
- Separate roles per concern (infra, deploy, backfill) and per environment
- Branch scoping: only `main` can assume apply/deploy roles
- Read-only plan role for PRs (any branch)

### 13.3 Infrastructure Pipeline

```
PR: terraform fmt → validate → Checkov → plan → comment on PR
Main: terraform apply (dev auto, prod approval gate)
```

### 13.4 Lambda Pipeline

```
PR: ruff lint → pytest → package → upload zip to S3
Main: deploy from S3 to dev (auto), prod (approval gate)
```

### 13.5 Lambda Artifacts

| Setting | Value |
|---|---|
| Storage | S3 bucket: `sisyfix-lambda-artifacts` (versioned) |
| Key pattern | `nvd-sync/{git-sha}/lambda.zip` |
| Metadata | `git-sha`, `built-at` tags |
| Lifecycle | Delete objects older than 90 days, keep last 20 versions |
| Promotion | Same S3 artifact deployed to dev and prod (same SHA) |

### 13.6 Deployment Ordering

When both `infra/` and `lambdas/` change in same PR:
1. Terraform applies first (infra before code)
2. Lambda deploys second (enforced via job dependencies)
3. If Terraform fails, Lambda deploy does not run

### 13.7 Production Promotion

- Same tested SHA — Lambda uses same S3 artifact, Terraform pins checkout to same commit
- GitHub Environment protection rules: prod requires manual approval
- Dev deploys automatically on merge to main

### 13.8 Security Scanning

- Checkov for Terraform (static HCL + plan output)
- Gate policy: CRITICAL/HIGH blocks PR, MEDIUM/LOW warnings only
- Existing Bandit/Semgrep extended to cover `lambdas/` directory

### 13.9 Secrets

| Secret | Storage | Used By |
|---|---|---|
| NVD API key | SSM Parameter Store (SecureString) | Lambda (cold start read), backfill script |
| AWS credentials | GitHub OIDC (no secrets stored) | All CI workflows |

---

## 14. IAM Policy Design

### 14.1 Principles

- Least privilege: minimum permissions for each identity
- Resource-scoped by ARN (no wildcards)
- `sisyfix-*` naming prefix constrains all roles
- Explicit deny for prod on dev roles
- Separate roles per environment and per concern

### 14.2 Role Inventory

| Role | Trust | Purpose | Deny |
|---|---|---|---|
| `sisyfix-github-infra-plan` | Any branch | Read-only plan for PRs | — |
| `sisyfix-github-infra-dev` | `main` only | Terraform apply to dev | `sisyfix-prod-*` |
| `sisyfix-github-infra-prod` | `main` only | Terraform apply to prod | — |
| `sisyfix-github-lambda-deploy-dev` | `main` only | Deploy Lambda code to dev | `sisyfix-prod-*` |
| `sisyfix-github-lambda-deploy-prod` | `main` only | Deploy Lambda code to prod | — |
| `sisyfix-github-backfill-dev` | `main` only | Write backfill data to dev | `sisyfix-prod-*` |
| `sisyfix-github-backfill-prod` | `main` only | Write backfill data to prod | — |
| `sisyfix-lambda-execution-{env}` | Lambda service | Runtime permissions for sync Lambda | — |
| `sisyfix-api-application-{env}` | API hosting | Read-only DynamoDB for enrichment | — |
| `sisyfix-break-glass-operator` | Human (MFA required) | PITR restore, emergency operations | — |

### 14.3 Lambda Execution Role Permissions

```
dynamodb:GetItem, PutItem, UpdateItem, BatchWriteItem (intelligence table)
ssm:GetParameter (/sisyfix/{env}/nvd-api-key)
logs:CreateLogGroup, CreateLogStream, PutLogEvents (/aws/lambda/sisyfix-{env}-nvd-sync)
sqs:SendMessage (DLQ)
```

### 14.4 API Application Role Permissions

```
dynamodb:GetItem, BatchGetItem (intelligence table — read-only)
ssm:GetParameter (/sisyfix/{env}/nvd-api-key)
```

### 14.5 Lambda Deploy Role Permissions

```
lambda:UpdateFunctionCode, GetFunction, PublishVersion, UpdateAlias, GetAlias, CreateAlias (sisyfix-*)
s3:PutObject, GetObject (sisyfix-lambda-artifacts/*)
```

### 14.6 KMS Policy

- AWS-managed SSM key (no customer-managed key)
- Explicit `kms:Decrypt` removed from policies (validate during implementation)
- Add back with `kms:ViaService` condition only if needed

### 14.7 Break-Glass Role

- For PITR restore and emergency operations only
- Requires MFA to assume
- 1-hour session maximum
- Permissions: `dynamodb:RestoreTableToPointInTime`, `DescribeTable`, `DescribeContinuousBackups`
- Never used by CI/CD

### 14.8 Terraform Resource Tagging

```hcl
provider "aws" {
  default_tags {
    tags = {
      Project     = "sisyfix"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
```

### 14.9 Validation Note

This is a design-time permission set. Will be validated and refined during first `terraform apply`. Missing permissions will be added narrowly, never with wildcards.

---

## 15. Monitoring and Alerting

### 15.1 Approach

- CloudWatch Embedded Metric Format (EMF) for custom metrics ($0 incremental cost)
- SQS Dead Letter Queue for failed Lambda invocations ($0 at this scale)
- Standard CloudWatch alarms ($0.10 each)
- No dashboard (use CloudWatch Insights ad-hoc queries)

### 15.2 Custom Metrics (via EMF)

| Metric | Purpose |
|---|---|
| `ItemsWritten` | Write volume trending |
| `ItemsSkipped` | Detect stale feed issues |
| `SyncDurationMs` | Performance trending |
| `Errors` | Error rate |
| `GapHours` | Drift detection |
| `CacheMissesNotFound` | Scanner emitting invalid CVE IDs |
| `CacheMissesLookupFailed` | NVD availability issues |

### 15.3 Alarms

| Alarm | Metric | Threshold | Action |
|---|---|---|---|
| Lambda errors | `AWS/Lambda/Errors` | > 0 for 2 consecutive runs | Email alert |
| DLQ depth | `AWS/SQS/ApproximateNumberOfMessagesVisible` | > 0 | Email alert |
| Sync gap | Custom EMF `GapHours` | > 24 hours | Email alert |
| Lambda duration | `AWS/Lambda/Duration` | > 250,000 ms | Email alert |

### 15.4 SQS Dead Letter Queue

| Setting | Value |
|---|---|
| Queue name | `sisyfix-{env}-nvd-sync-dlq` |
| EventBridge retry config | Max 2 retries, max event age 6 hours |
| On DLQ message | CloudWatch alarm triggers |

---

## 16. Cost Estimates

### 16.1 Monthly Costs (No Free Tier)

| Component | Dev | Prod | Combined |
|---|---|---|---|
| DynamoDB (storage + R/W) | ~$0.36 | ~$0.94 | $1.30 |
| Lambda | ~$0.02 | ~$0.14 | $0.16 |
| EventBridge | $0 | $0 | $0 |
| SQS DLQ | $0 | $0 | $0 |
| CloudWatch (logs + alarms) | ~$0.35 | ~$0.45 | $0.80 |
| S3 (Terraform state + Lambda artifacts) | ~$0.02 | ~$0.02 | $0.04 |
| SSM Parameter Store | $0 | $0 | $0 |
| **Total** | **~$0.75** | **~$1.55** | **~$2.30** |

### 16.2 One-Time Costs

| Item | Cost |
|---|---|
| Historical backfill (~200K writes) | ~$0.31 per environment |
| Total initial setup | ~$0.62 |

### 16.3 Future Cost Impact (EPSS/KEV/MITRE Added)

| Scenario | Additional Monthly Cost |
|---|---|
| EPSS with delta optimization | ~$0.15-0.63 |
| KEV (5-10 items/day) | negligible |
| MITRE (monthly refresh) | negligible |
| **Total with all sources** | **~$3-5 combined** |

---

## 17. Rollback Strategy

### 17.1 Lambda Rollback

| Method | Time | Action |
|---|---|---|
| Redeploy previous S3 artifact | ~10 seconds | `aws lambda update-function-code --s3-key nvd-sync/{previous-sha}/lambda.zip` |
| Emergency stop | ~10 seconds | `aws events disable-rule --name sisyfix-{env}-nvd-sync-schedule` |

### 17.2 Terraform Rollback

| Method | Time | Action |
|---|---|---|
| Revert commit + apply | ~2-5 minutes | `git revert` → `terraform apply` |
| Targeted resource removal | ~1 minute | `terraform destroy -target=resource` |
| State recovery | ~5 minutes | Restore versioned state file from S3 |

### 17.3 DynamoDB Data Rollback

| Method | Time | Action |
|---|---|---|
| PITR restore | ~10-30 minutes | Restore to new table → validate → swap |
| Re-run backfill | ~15 minutes | Idempotent — overwrites bad data |
| Emergency: disable sync | ~10 seconds | Disable EventBridge rule |

### 17.4 Recovery Permissions

PITR restore is reserved for human operators via break-glass role with MFA. Not available to CI/CD.

---

## 18. Future Considerations

### 18.1 Not Built Now, Designed For

| Feature | Trigger to Build |
|---|---|
| EPSS sync Lambda | When EPSS enrichment moves from API to DynamoDB |
| KEV sync Lambda | When KEV enrichment moves from API to DynamoDB |
| MITRE sync to DynamoDB | When MITRE data migrates from Supabase |
| DynamoDB GSIs | When analytics/reporting use cases emerge |
| DAX cache layer | When read traffic exceeds 1000s/second |
| Async cache-miss (SQS + worker) | When cache misses consistently > 5 per batch |
| Lambda versions/aliases | When instant alias-swap rollback is needed |
| Multi-region (Global Tables) | When disaster recovery across regions is required |
| Customer-managed KMS key | When compliance mandates key rotation auditing |
| Staging environment | When team size grows or pre-prod gate is needed |

### 18.2 Terraform State Bootstrap

One-time manual setup required before first `terraform apply`:

```bash
# bootstrap.sh
aws s3api create-bucket --bucket sisyfix-terraform-state --region us-east-1
aws s3api put-bucket-versioning --bucket sisyfix-terraform-state --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket sisyfix-terraform-state --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
aws dynamodb create-table --table-name sisyfix-terraform-locks --attribute-definitions AttributeName=LockID,AttributeType=S --key-schema AttributeName=LockID,KeyType=HASH --billing-mode PAY_PER_REQUEST
aws s3api create-bucket --bucket sisyfix-lambda-artifacts --region us-east-1
aws s3api put-bucket-versioning --bucket sisyfix-lambda-artifacts --versioning-configuration Status=Enabled
```

### 18.3 OIDC Provider Bootstrap

One-time setup of GitHub OIDC identity provider in AWS:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

---

## Appendix A: ADR Template

```markdown
# ADR-{number}: {Title}

**Date:** YYYY-MM-DD
**Status:** Proposed | Accepted | Deprecated | Superseded

## Context
What is the issue or decision we're facing?

## Decision
What did we decide?

## Consequences
What are the positive and negative implications?
```

---

## Appendix B: Implementation Tasks (High Level)

| # | Task | Dependencies | Est. Effort |
|---|---|---|---|
| 1 | Bootstrap AWS (S3, DynamoDB lock, OIDC provider) | None | 1-2 hours |
| 2 | Terraform modules (DynamoDB, IAM, Lambda, EventBridge, SQS, Monitoring) | Task 1 | 4-6 hours |
| 3 | Terraform environments (dev.tfvars, prod.tfvars, backend.tf) | Task 2 | 1-2 hours |
| 4 | Lambda shared code (feed_ingestion, dynamo_writer, checkpoint, models) | None | 3-4 hours |
| 5 | NVD transformer (NVD 2.0 JSON → DynamoDB item shape) | Task 4 | 2-3 hours |
| 6 | Lambda handler (sync logic, gap detection, error handling) | Tasks 4, 5 | 3-4 hours |
| 7 | Backfill CLI script | Tasks 4, 5 | 2-3 hours |
| 8 | Intelligence service (`apps/api/app/services/intelligence.py`) | None | 2-3 hours |
| 9 | Sub-agent 2 integration (replace API calls with intelligence service) | Task 8 | 2-3 hours |
| 10 | CI/CD workflows (infra.yml, lambda-deploy.yml, backfill.yml, drift) | Tasks 2, 6 | 3-4 hours |
| 11 | Tests (transformer, handler, intelligence service) | Tasks 5, 6, 8 | 3-4 hours |
| 12 | Documentation (ADRs, runbooks) | All | 2-3 hours |
| 13 | Deploy to dev + run backfill + validate | All above | 2-3 hours |
| 14 | Deploy to prod + run backfill + validate | Task 13 | 1-2 hours |

**Total estimated implementation: ~30-45 hours**
