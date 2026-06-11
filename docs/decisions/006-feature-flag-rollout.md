# ADR-006: Feature Flag for Intelligence Service Rollout

**Status:** Accepted  
**Date:** 2024-01  
**Deciders:** Platform team

## Context

The Intelligence Service replaces direct NVD API calls in the enrichment pipeline with local DynamoDB lookups. This is a significant change to the data path — if the local data is stale, incomplete, or the service has bugs, enrichment quality could degrade.

We need a strategy for safely rolling out this change.

## Decision

Gate the Intelligence Service behind a **feature flag** (`intelligence_enabled`) in the API configuration. When disabled, the system falls back to the existing direct NVD API path.

## Implementation

```python
# apps/api/app/config.py
class Settings(BaseSettings):
    intelligence_enabled: bool = False  # Default OFF
    intelligence_table_name: str = ""
    intelligence_aws_region: str = "us-east-1"
```

```python
# apps/api/app/agents/sub_agent_2.py
if settings.intelligence_enabled:
    result = intelligence_service.get_cve_intelligence(cve_id)
else:
    result = legacy_nvd_api_lookup(cve_id)
```

## Rollout Plan

1. **Deploy with flag OFF** — Intelligence Service code is deployed but inactive
2. **Run backfill** — populate DynamoDB with historical data
3. **Validate data quality** — compare DynamoDB results vs. live NVD API for sample CVEs
4. **Enable in dev** — set `intelligence_enabled=True` in dev environment
5. **Monitor for 1 week** — check cache miss rates, lookup latency, enrichment completeness
6. **Enable in prod** — flip the flag in production after dev validation

## Consequences

**Positive:**
- Zero-risk deployment — code ships without changing behavior
- Instant rollback — set flag to `False` to revert to legacy path
- Independent of data readiness — can deploy code before backfill completes
- Gradual confidence building — validate in dev before prod

**Negative:**
- Two code paths to maintain temporarily (legacy + intelligence service)
- Flag must be removed eventually to avoid dead code (tech debt if forgotten)
- Testing must cover both paths (flag on and flag off)

**Exit criteria for removing the flag:**
- Intelligence Service running in prod for 30+ days without issues
- Cache miss rate below threshold consistently
- No enrichment quality regressions reported
- Legacy NVD API path removed, flag deleted
