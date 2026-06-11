# ADR-001: DynamoDB Over RDS for Intelligence Storage

**Status:** Accepted  
**Date:** 2024-01  
**Deciders:** Platform team

## Context

We need a data store for vulnerability intelligence records (CVE data from NVD, and future sources like EPSS, KEV, MITRE). The store must support:

- High-throughput batch writes during sync (thousands of items per run)
- Low-latency reads for enrichment (sub-200ms for up to 100 items)
- Simple key-value access patterns (lookup by CVE ID, batch get by multiple IDs)
- Pay-per-use pricing (traffic is bursty — sync every 2 hours, reads during scans)
- Minimal operational overhead (no patching, no connection pooling)

Options considered:
1. **DynamoDB** — managed NoSQL, PAY_PER_REQUEST, single-digit-ms reads
2. **RDS PostgreSQL** — managed relational, connection pooling needed, provisioned capacity
3. **ElastiCache (Redis)** — in-memory, fast but volatile, cost grows with data size

## Decision

Use **DynamoDB with PAY_PER_REQUEST billing** and a single-table design.

## Rationale

- **Access patterns are simple key lookups** — no joins, no aggregations, no full-text search. DynamoDB excels at this.
- **PAY_PER_REQUEST eliminates capacity planning** — we don't know read/write traffic until production; on-demand scales automatically.
- **BatchGetItem supports our batch read pattern** — up to 100 keys in one call, exactly matching our use case.
- **No connection management** — Lambda functions don't need connection pools, VPCs, or security groups for DynamoDB access.
- **Built-in PITR** — point-in-time recovery for disaster scenarios without managing backups.
- **Cost predictable** — at our expected scale (~250K CVEs, reads during scans), costs are minimal compared to a provisioned RDS instance running 24/7.

## Why Not RDS?

- Requires VPC placement for Lambda → adds cold start latency and complexity
- Connection pooling (RDS Proxy) adds cost and another failure point
- Provisioned instance runs 24/7 even when idle between syncs
- Schema migrations needed for adding new intelligence sources
- Overkill for key-value access patterns

## Why Not Redis?

- Volatile — data lost on restart unless using persistence (which adds latency)
- Cost scales linearly with data size (250K+ items with nested data)
- No built-in backup/restore comparable to PITR
- Better suited for caching, not primary storage

## Consequences

**Positive:**
- Zero operational overhead for capacity management
- Consistent sub-10ms latency for single gets, sub-50ms for batch gets
- Adding new sources just means adding new fields — no migrations
- PITR provides disaster recovery without custom backup scripts

**Negative:**
- 400KB item size limit (not an issue for CVE records, ~2-5KB each)
- No ad-hoc SQL queries for analytics (must export to S3/Athena if needed)
- Conditional writes require careful expression design
- BatchWriteItem limited to 25 items (requires partitioning logic)

**Risks:**
- If access patterns change significantly (e.g., full-text search on descriptions), we may need a secondary store
- Hot partition possible if many CVEs share a prefix — mitigated by CVE IDs being naturally distributed
