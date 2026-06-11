# ADR-003: NVD Feed Files Over API for Ongoing Sync

**Status:** Accepted  
**Date:** 2024-01  
**Deciders:** Platform team

## Context

NVD provides two mechanisms for obtaining vulnerability data:

1. **JSON Feed Files** — pre-built `.json.gz` files containing all CVEs modified within a time window (modified feed covers last 8 days, yearly feeds for historical data)
2. **NVD 2.0 REST API** — paginated API with query parameters for date ranges, requires API key, rate limited to 50 requests per 30 seconds

We need to decide which mechanism to use for ongoing periodic synchronization.

## Decision

Use **NVD feed files** as the primary sync mechanism for ongoing synchronization, with the **NVD API** as a fallback for gap recovery (gaps between 8 and 120 days).

## Rationale

**Feed files for normal sync:**
- Single HTTP request downloads all modified CVEs (vs. potentially hundreds of paginated API calls)
- META file enables cheap change detection — skip download if hash is unchanged
- No rate limiting concerns for feed file downloads
- Faster execution — one download + decompress vs. sequential paginated requests with rate limiting
- Simpler error handling — one request to succeed or fail
- Deterministic execution time — feed size is bounded and predictable

**API for gap recovery only:**
- Feed files only cover 8 days — if sync misses more than 8 days, feeds can't recover the gap
- API allows querying by arbitrary date range with `lastModStartDate`
- Gap recovery is rare (only after extended outages) so rate limiting is tolerable
- Fallback path, not the primary sync mechanism

## Consequences

**Positive:**
- Normal sync completes in seconds (single download + batch write)
- No API key needed for normal sync path
- META hash comparison provides free "nothing changed" detection
- Predictable Lambda execution duration (feed size is bounded)

**Negative:**
- Feed files contain all CVEs modified in 8 days, not just since our last checkpoint — requires filtering
- If NVD discontinues feed files, we'd need to switch to API-only (low risk — feeds have been stable for years)
- Gap recovery path is more complex (pagination, rate limiting, API key management)

**Boundary conditions:**
- Gap < 8 days → use feed file (normal path)
- Gap 8–120 days → use API (gap recovery path)
- Gap > 120 days → abort, require manual backfill (too many CVEs to safely recover in one Lambda invocation)
