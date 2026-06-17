# ADR-002: Single-Table Design for Intelligence Data

**Status:** Accepted  
**Date:** 2024-01  
**Deciders:** Platform team

## Context

We have multiple entity types to store:
- CVE intelligence records (~250K items)
- CWE/MITRE mappings (~1K items)
- Sync checkpoints (1 per source)
- Backfill progress (1 per source)

We need to decide between:
1. **Single table** with a `pk`/`sk` composite key and entity-type prefixes
2. **Multiple tables** — one per entity type (cve-intelligence, mitre-mappings, sync-state)

## Decision

Use a **single DynamoDB table** with a `pk` (partition key) and `sk` (sort key) composite key. Entity types are distinguished by key prefixes:

- `CVE#{id}` / `INTEL` — CVE intelligence
- `CWE#{id}` / `MITRE` — CWE mappings
- `SYSTEM#SYNC` / `{source}` — sync checkpoints
- `SYSTEM#BACKFILL` / `{source}` — backfill progress

## Rationale

- **One table to provision, monitor, and manage** — simpler Terraform, fewer alarms, one PITR policy
- **All access patterns are point lookups** — no need for GSIs or table scans
- **Atomic operations across entity types** — could use transactions if needed (e.g., write CVE + update checkpoint atomically)
- **Future sources extend the same items** — adding EPSS data means writing to the `epss` field on existing `CVE#` items, not a new table
- **Cost efficiency** — PAY_PER_REQUEST billing is per-table; one table means one billing surface

## Consequences

**Positive:**
- Single IAM policy, single backup policy, single monitoring configuration
- Adding new intelligence sources requires zero table changes
- Simpler Terraform module (one `aws_dynamodb_table` resource)
- Checkpoint reads and CVE writes can eventually use transactions for stronger consistency

**Negative:**
- Key design requires prefix conventions (documented in [dynamo-schema.md](../architecture/dynamo-schema.md))
- Item collections can't be heterogeneous without careful sk design (not an issue — each pk has exactly one sk)
- Harder to independently scale read/write capacity per entity type (mitigated by PAY_PER_REQUEST)

**Trade-offs accepted:**
- We trade query flexibility for operational simplicity
- We accept the cognitive overhead of key conventions in exchange for infrastructure simplicity
