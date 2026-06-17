# Data Flow

## Sync Pipeline (Normal Path)

The primary data flow for keeping intelligence data current.

```
EventBridge (schedule)
    │
    ▼
┌─────────────────────────────────────────────┐
│  Sync Lambda                                 │
│                                             │
│  1. Read checkpoint from DynamoDB           │
│     pk=SYSTEM#SYNC, sk=NVD                  │
│     → last_successful_sync, meta_sha256     │
│                                             │
│  2. Fetch META file from NVD                │
│     → Compare SHA-256 hash                  │
│     → If unchanged: EXIT EARLY (no work)    │
│                                             │
│  3. Download modified feed (.json.gz)       │
│     → Streaming decompression in memory     │
│     → Parse JSON → "vulnerabilities" array  │
│                                             │
│  4. Filter CVEs                             │
│     → Keep only items where                 │
│       lastModified > checkpoint_timestamp   │
│                                             │
│  5. Transform each CVE                      │
│     → NVD 2.0 JSON → DynamoDB item schema   │
│     → Pure function (no I/O)                │
│     → Skip malformed items (log + continue) │
│                                             │
│  6. Batch write (25 items per request)      │
│     → Check remaining time before each batch│
│     → Abort if <30s remaining               │
│     → Retry UnprocessedItems (3x, exp bo)   │
│                                             │
│  7. Update checkpoint                       │
│     → Only after ALL writes succeed         │
│     → New timestamp = max(lastModified)     │
│     → Store new META hash                   │
└─────────────────────────────────────────────┘
```

## Gap Recovery Path

Triggered when gap between checkpoint and now is 8–120 days (modified feed only covers 8 days).

```
Sync Lambda detects gap ≥ 8 days
    │
    ▼
┌─────────────────────────────────────────────┐
│  Gap Recovery Module                         │
│                                             │
│  1. Read NVD API key from SSM               │
│     /sisyfix/{env}/nvd-api-key              │
│     → Cached in memory (warm starts)        │
│                                             │
│  2. Query NVD API (paginated)               │
│     lastModStartDate = checkpoint           │
│     lastModEndDate = now                    │
│     resultsPerPage = 2000                   │
│                                             │
│  3. Rate limit                              │
│     → Max 50 requests per 30s window        │
│     → Rolling window enforcement            │
│                                             │
│  4. Retry on failure                        │
│     → 3 attempts with exponential backoff   │
│     → Abort on persistent failure           │
│                                             │
│  5. Return CVE items → normal pipeline      │
│     → Transform → Batch write → Checkpoint  │
└─────────────────────────────────────────────┘
```

## Critical Gap (≥120 days)

When the gap exceeds 120 days, automatic recovery is unsafe (too many CVEs, risk of incomplete state).

```
Sync Lambda detects gap ≥ 120 days
    │
    ▼
┌─────────────────────────────────────────────┐
│  CRITICAL: Manual intervention required      │
│                                             │
│  - Emit CRITICAL log event                  │
│  - Trigger CloudWatch alarm → SNS           │
│  - Checkpoint unchanged                     │
│  - Exit without processing                  │
│                                             │
│  Resolution: Run backfill CLI manually      │
└─────────────────────────────────────────────┘
```

## Backfill Flow

One-time or recovery bulk load of historical data.

```
Operator triggers (GitHub Actions or manual)
    │
    ▼
┌─────────────────────────────────────────────┐
│  Backfill CLI                                │
│                                             │
│  1. Check backfill checkpoint               │
│     pk=SYSTEM#BACKFILL, sk=NVD              │
│     → Resume from last_completed_year       │
│                                             │
│  2. For each year (2016–2026):              │
│     a. Download yearly feed (.json.gz)      │
│     b. Decompress in memory                 │
│     c. Transform each CVE (same transformer)│
│     d. Batch write (25/batch, 3x retry)     │
│     e. Update backfill checkpoint (year)    │
│                                             │
│  3. On completion:                          │
│     → Set sync checkpoint to now            │
│     → Future syncs pick up from here        │
│                                             │
│  Error handling:                            │
│     → Malformed item: skip + warn           │
│     → Download failure: abort, checkpoint   │
│       preserved at last completed year      │
│     → Write failure: abort, same behavior   │
└─────────────────────────────────────────────┘
```

## Read Path (Intelligence Service)

How the FastAPI backend queries intelligence data.

```
Enrichment Agent (sub_agent_2.py)
    │
    │  if intelligence_enabled:
    ▼
┌─────────────────────────────────────────────┐
│  VulnIntelligenceService                     │
│                                             │
│  batch_get_cve_intelligence(cve_ids)        │
│     → DynamoDB BatchGetItem                 │
│     → Up to 100 keys per request            │
│     → Retry UnprocessedKeys (3x)            │
│                                             │
│  Returns for each CVE:                      │
│     Found → CveIntelligence(resolved)       │
│     Not found → CveIntelligence(lookup_failed)│
│     DynamoDB error → CveIntelligence(lookup_failed)│
│                                             │
│  Never raises unhandled exception.          │
│  Never writes to DynamoDB (read-only IAM).  │
└─────────────────────────────────────────────┘
    │
    │  if NOT intelligence_enabled:
    ▼
┌─────────────────────────────────────────────┐
│  Legacy path: Direct NVD API calls          │
│  (rate-limited, slower, still available)    │
└─────────────────────────────────────────────┘
```

## Failure and Recovery Matrix

| Failure Point | Impact | Automatic Recovery |
|--------------|--------|-------------------|
| META fetch fails | Sync aborted | Next scheduled run retries |
| Feed download fails | Sync aborted | Next scheduled run retries |
| Transform fails (1 item) | Item skipped | Logged, rest processed |
| Batch write fails (transient) | Batch delayed | Retry 3x with backoff |
| Batch write fails (persistent) | Sync aborted | Next run from same checkpoint |
| Lambda timeout | Sync aborted | Checkpoint unchanged, next run continues |
| NVD API down (gap recovery) | Recovery aborted | Next run retries gap recovery |
| DynamoDB down (read path) | Lookups degraded | Returns `lookup_failed`, no crash |
| Gap > 120 days | Sync blocked | CRITICAL alert, manual backfill needed |
