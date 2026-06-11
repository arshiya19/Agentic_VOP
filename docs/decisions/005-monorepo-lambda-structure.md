# ADR-005: Lambda Code in Monorepo Over Separate Repository

**Status:** Accepted  
**Date:** 2024-01  
**Deciders:** Platform team

## Context

The Sisyfix project is a monorepo containing the web frontend (`apps/web/`), FastAPI backend (`apps/api/`), and infrastructure (`infra/`). We need to decide where the NVD sync Lambda code lives:

1. **In the monorepo** — new `lambdas/` directory alongside existing code
2. **Separate repository** — dedicated repo for Lambda functions

## Decision

Keep Lambda code **in the monorepo** under `lambdas/`.

## Rationale

- **Shared transformer** — the Intelligence Service in `apps/api/` reads data written by the Lambda's transformer. Having both in the same repo ensures schema consistency.
- **Atomic changes** — infrastructure + Lambda + API service changes can land in a single PR with coordinated review
- **CI/CD simplicity** — one set of workflows, path-based triggers (`lambdas/**`, `infra/**`, `apps/api/**`)
- **Shared Terraform state references** — Lambda ARN output is used by EventBridge, IAM references DynamoDB table ARN. All in one Terraform root.
- **Reduced context switching** — contributors see the full system in one place

## Structure

```
lambdas/
├── shared/           # Source-agnostic feed ingestion framework
│   ├── feed_ingestion.py
│   ├── dynamo_writer.py
│   ├── checkpoint.py
│   ├── emf_logger.py
│   └── exceptions.py
├── nvd_sync/         # NVD-specific handler, transformer, config
│   ├── handler.py
│   ├── transformer.py
│   ├── config.py
│   ├── gap_recovery.py
│   ├── backfill.py
│   └── tests/
└── requirements.txt  # Lambda-specific pinned dependencies
```

## Consequences

**Positive:**
- One repo, one CI/CD system, one review process
- Schema changes between writer (Lambda) and reader (API service) are always in sync
- Easier onboarding — the full system is discoverable in one place
- Path-based workflow triggers keep builds fast (only run Lambda CI when `lambdas/` changes)

**Negative:**
- Lambda packaging must exclude non-Lambda code (handled by CI/CD zip step)
- Different dependency sets (Lambda has `boto3`+`urllib3`, API has FastAPI+OpenAI) — managed via separate `requirements.txt`
- Repository grows larger over time (mitigated: Lambda code is small, ~1000 LOC)

**Mitigation:**
- CI/CD `check-changes` step determines which paths changed and skips irrelevant jobs
- Lambda packaging script explicitly copies only `lambdas/shared/` and `lambdas/nvd_sync/`
