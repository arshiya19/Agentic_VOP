# Remediation Engine — Sub-Agent 3 + Pattern Library + Confidence

Phase-1 implementation of the AI Remediation Working Model (spec v1.1). This
folder is the layer that runs **after Sub-Agent 2 (prioritization)** and turns
a prioritized `issues` row into a full **Remediation Package** — a structured
artifact with cited fix steps, an explainable rollback plan, runnable test
scripts, and a deterministic confidence score.

This README assumes **you've never seen this code before**. It walks the files,
the data model, why we made each architectural call, and how to run / iterate.

> Big picture: [`../../../../README.md`](../../../../README.md) · Backend guide: [`../../../README.md`](../../../README.md) · DB schema: [`../../../../../supabase/README.md`](../../../../../supabase/README.md)

---

## 1. The 60-second pitch

An issue lands in the `issues` table after Sub-Agent 1 (normalize) + Sub-Agent 2
(enrich + score). Today the pipeline stops there. Phase-1 adds this remediation folder:

1. Operator (or CLI) triggers **`plan_remediation(issue)`**.
2. **`classifier.py`** deterministically maps the issue to one of 5 families
   (public_exposure / network_exposure / injection / vulnerable_dependency /
   os_vulnerability). Pure rules, no LLM.
3. **`planner.py`** loads the matching row from **`remediation_patterns`** — a
   hand-curated table with 6-10 ordered fix steps, rollback steps, validation
   tests, and test-script templates, every step citing a real authority (AWS
   docs, CIS, OWASP, MITRE, NVD, CISA KEV).
4. **Sub-Agent 3** (a `gpt-4o` LLM with a structured-output schema) receives
   the issue + asset context + pattern. It substitutes placeholders
   (`{bucket_name}` → `acme-customer-exports-prod`) and writes short
   Finding / Root Cause / Impact prose. **It cannot invent steps or sources.**
5. **`confidence.py`** runs a deterministic 5-factor formula and produces a
   0-100 score + component breakdown + approval requirement.
6. **`persist_package()`** writes the whole thing to `remediation_packages`.
7. The frontend `/remediation` page reads that table and lets a human
   Approve / Reject via `POST /admin/remediation-packages/{id}/(approve|reject)`.

Result: one durable, auditable, human-gated **Validated Remediation Package**
per issue, with every step traceable to a citable source.

---

## 2. Where this sits in the bigger pipeline

```
Scanner file upload
     ↓
Sub-Agent 1 (normalize)              ← apps/api/app/agents/sub_agent_1.py
     ↓
Sub-Agent 2 (enrich + score)         ← apps/api/app/agents/sub_agent_2.py
     ↓
issues table (prioritized findings)  ← Master pipeline ENDS here today
     ↓
     ─── Phase-1 Remediation Engine (this folder) ───
     ↓
classify_finding(issue) → family     ← classifier.py
     ↓
Sub-Agent 3 (planner LLM)            ← planner.py + prompt_db.'sub-agent-3'.v1.3
     ↓
compute_confidence(...)              ← confidence.py
     ↓
persist_package(...)                 ← planner.py :: persist_package
     ↓
remediation_packages table
     ↓
GET /admin/remediation-packages      ← main.py endpoints
     ↓
/remediation page                    ← apps/web/src/pages/remediation.jsx
     ↓
Approve / Reject state machine       ← main.py + status column
```

**Important:** Sub-Agent 3 is NOT wired into the Master LangGraph yet. It runs
on-demand only, via the CLI or the `/admin/remediation-packages/generate`
endpoint. This is a Phase-1 cost-control choice — auto-wiring it into Master
would fan out to every new issue and blow the LLM budget without careful
guardrails. Phase-2 adds those guardrails and the auto-triggers.

---

## 3. Architectural decisions (the "why")

Non-obvious calls baked into this codebase. Worth knowing before reading the code.

### Hybrid Pattern + AI (rejected: pure-LLM + pure-rules)
Per spec §15, we deliberately did NOT build a pure-LLM remediation ("write me a
fix for this CVE") because the outputs would be non-deterministic and
un-auditable. We also did NOT build a pure-rule engine ("if CVE-X then do Y")
because it doesn't scale beyond hand-written cases. The hybrid split:
- **Pattern library** (SQL rows) = the deterministic, human-curated, cited
  fix template — 5 families cover every Phase-1 demo issue.
- **LLM (Sub-Agent 3)** = context-aware adapter that fills placeholders + writes
  short prose. Cannot invent steps or sources.
- **Confidence engine** (Python formula) = the score. Never the LLM's job.

### No fine-tuning
Stock `gpt-4o` with a versioned prompt in `prompt_db`. Iteration = SQL UPDATE
on the prompt row. No training data, no model weights, no retraining. Full
auditability: read the prompt, see exactly what we ask.

### Prompts live in the database
Sub-Agent 3's prompt is in `prompt_db` (agent=`sub-agent-3`, currently
`version='v1.3'`, `is_active=true`). Same convention as Sub-Agent 1 + 2.
Bumping the prompt version = new INSERT + deactivate old row. No code deploy
required.

### Structured output enforced by the API
`invoke_structured_with_retry(schema=LLMRemediationOutput, ...)` uses OpenAI
function-calling. The LLM's response is **guaranteed** to match the Pydantic
schema — no `json.loads()`, no parsing bugs. Failed shape = automatic retry
with tier-escalating temperature and model.

### Determinism where possible
Family classification (`classifier.py`) is pure Python rules — cheap,
microsecond-fast, same input always produces same output. We only escalate to
the LLM for the actual per-issue adaptation. Confidence scoring is also pure
Python (5-factor formula, no LLM).

### Rich step format inside a single field (no schema change)
Each pattern's `canonical_steps[].step` field carries a multi-line text blob
with `Action / Command: <cli> / Why: <rationale>` sections. We chose to embed
this in the existing text field (max length bumped to 2000 chars) instead of
splitting into separate columns. Rationale: keeps the RemediationStep Pydantic
schema stable across v1.0 → v1.3 iterations, and the UI just renders with
`white-space: pre-wrap`.

### Explainable rollback (spec §7.2)
Every pathway has a structured `rollback_plan` object with `objective`,
`preconditions`, `steps`, `limitations`, and — most importantly — an
`explanation` field that justifies WHEN rollback is safe to invoke and when
it isn't. Never "just revert to version X" — always "here's what you
re-expose if you roll back, and here's when that's acceptable."

### Mandatory test_scripts
Every package must ship 2-3 runnable test scripts (bash / python / hcl). The
pattern provides `test_script_templates`; the LLM fills placeholders. No more
"generic guidance" — the operator can copy-paste the fix + verify it worked.

### Pathways-aware schema (Phase-2 ready)
The output shape uses a `pathways[]` array even though Phase-1 always emits
exactly 1 pathway. This is per spec §7.3 — the data model already supports
multi-pathway (e.g. Log4j upgrade vs interim JndiLookup removal) without
architectural change. Phase-2 flips this on for select families.

### Append-only packages
Same principle as `issues` table. Each regeneration inserts a new row rather
than updating in place. Full audit trail of every LLM-generated version.
Phase-2 adds a "current" view on top for the operator UI.

### Validation status tiered by source authority
`planner.py :: _classify_source_tier` maps each `primary_source` to a tier per
spec §7.1:
- **Tier 1-3** (vendor docs, NVD, CISA KEV) → `validated / high`
- **Tier 4-5** (OWASP, MITRE, CIS) → `partial / medium`
- **Missing** → `unvalidated / low`

Honest down-grading. The SQL injection package lands as "partial" because
OWASP is Tier 4 — we don't lie about how "authoritative" the sources are.

---

## 4. Files in this folder

### [`classifier.py`](./classifier.py) — deterministic family mapping
`classify_finding(issue) → family` walks a short list of yes/no rules and
returns one of `public_exposure`, `network_exposure`, `injection`,
`vulnerable_dependency`, `os_vulnerability`, or `unknown`. Pure Python, no
LLM, microseconds. Rules examine `issue.source`, `title`, `cwe_id`, and
`runtime_purl` — first match wins.

### [`planner.py`](./planner.py) — the orchestration
The main entry point.

- `plan_remediation(issue, run_id, sb) → RemediationPackage` — classifies,
  loads the pattern from `remediation_patterns`, builds the LLM payload
  (issue + asset via `issue_with_asset` view + pattern), calls Sub-Agent 3,
  runs `compute_confidence()` per pathway, attaches `validation_metadata`,
  picks the recommended pathway (highest confidence).
- `persist_package(pkg, run_id, sb) → id` — INSERTs into `remediation_packages`
  with `status='awaiting_approval'`. Returns the new row's ID.
- `_classify_source_tier(source)` — the source-tier mapper for
  validation_metadata.
- `_validation_metadata_for(pattern)` — builds the audit-trail object.

### [`confidence.py`](./confidence.py) — 5-factor deterministic scoring
Pure Python. Takes an assembled `RemediationPathway` + pattern + asset and
returns `{score: int, components: dict, approval_required: str}`.

The 5 factors (per spec §8, weights sum to 100):
- **Deterministic Fix** (30) — is action_type in the "config flip" set, or is
  it a code_change (partial credit)?
- **Blast Radius** (25) — log-scaled by affected asset count.
- **Test Coverage** (20) — >= 2 validation tests = full credit.
- **Rollback Availability** (15) — automatic / redeploy / manual / n_a. Also
  downgrades to 0 if the LLM said `rollback_plan.supported = false`.
- **Environmental Uncertainty** (10) — do we know enough about the deployment
  context (runtime_os_family, asset.environment)? Full credit for source-level
  families where runtime is irrelevant.

Approval policy:
- `priority=P0` AND `score < 80` → `multi_stage` (high-stakes, low-confidence)
- `score >= 90` AND `priority in (P2, P3)` → `auto` (routine, high-confidence)
- else → `single_approver` (default)

### [`__init__.py`](./__init__.py) — module marker
Empty file. Marks this directory as a Python package so
`from app.agents.remediation.planner import plan_remediation` works.

---

## 5. Data model

Two Supabase tables + one prompt row + a jsonb schema.

### `remediation_patterns` (migration `0036` + `0042`)
The curated knowledge base. 5 rows, one per family. Key columns:

| Column | What |
|---|---|
| `family` (PK) | one of the 5 family strings |
| `action_type` | `configuration_change` / `code_change` / `dependency_upgrade` / `package_upgrade` — drives the "Deterministic Fix" confidence factor |
| `canonical_steps` (jsonb) | array of 6-10 `{step, source, source_url}`. `step` is a rich text blob with Action + `Command:` + `Why:` sections. |
| `rollback_strategy` | `automatic` / `redeploy` / `manual` / `not_applicable` |
| `rollback_steps` (jsonb) | same shape as canonical_steps, for the rollback path |
| `validation_tests` (jsonb) | array of `{name, method, command_template, expected, source}` |
| `test_script_templates` (jsonb) | array of `{language, description, code}` — templates the LLM fills placeholders into |
| `primary_sources` (text[]) | top-level authority labels for the demo card |
| `confidence_base` | starting confidence per §8 (advisory, current engine uses fixed factor weights) |
| `notes` | internal hint the LLM sees in its payload |

Edit patterns via Supabase Table Editor — no code deploy needed.

### `remediation_packages` (migration `0041`)
One row per generated package. Key columns:

| Column | What |
|---|---|
| `id` | bigserial PK |
| `issue_id` (FK → issues) | which issue this fixes |
| `family` | copied from classifier output |
| `finding` / `root_cause` / `impact` | LLM prose (shared across pathways) |
| `pathways` (jsonb) | array of `RemediationPathway` objects — each has its own confidence, validation_metadata, rollback_plan, remediation_steps, validation_tests, test_scripts |
| `recommended_pathway_index` | which pathway the planner recommends |
| `approval_required` | `auto` / `single_approver` / `multi_stage` |
| `status` | `draft` → `awaiting_approval` → `approved` → `ready_for_execution` OR `rejected` |
| `approved_by` / `approved_at` / `rejected_reason` | audit columns |
| `agent_run_id` (FK → agent_runs) | which run created this package |

**Append-only.** Regeneration inserts new rows, never overwrites.

### `prompt_db` row for `sub-agent-3`
One active row. Current: `version='v1.3'`, `model='gpt-4o'`, `is_active=true`.
Version history:
- v1.0 (migration `0037`) — initial single-pathway shape
- v1.1 (migration `0039`) — restructured to pathways + structured RollbackPlan +
  ValidationMetadata per spec §7.2 / §7.3
- v1.1 patch (migration `0040`) — SAST placeholder fix
- v1.2 (migration `0043`) — rich step format (Action / Command / Why) +
  mandatory test_scripts. Model still gpt-4o-mini.
- v1.3 (migration `0044`) — tighter output schema, explicit INPUT→OUTPUT field
  mapping to stop LLM from mirroring input fields into output. Bumped to gpt-4o.

Deactivating an old version + inserting a new one is a single migration
transaction.

### Pydantic schemas ([`../../models.py`](../../models.py))
- `RemediationStep` — `{step, source, source_url}`. `step` max 2000 chars.
- `ValidationTest` — `{name, method, command, expected, source}`.
- `TestScript` — `{language, description, code}`. Language is a `Literal`.
- `RollbackPlan` — the structured explainable-rollback object.
- `ValidationMetadata` — `{status, sources, timestamp, confidence}`.
- `RemediationPathway` — one path with all the above + advantages / considerations.
- `LLMRemediationOutput` — what Sub-Agent 3 emits (finding / root_cause / impact
  / pathways).
- `RemediationPackage` — the persisted artifact (LLM output + issue_id + family
  + approval_required + recommended_pathway_index).

---

## 6. The 5 families (what each pattern covers)

| Family | Example finding | Action type | Rollback |
|---|---|---|---|
| `public_exposure` | S3 bucket with public-read ACL | `configuration_change` | automatic |
| `network_exposure` | Security group allowing 0.0.0.0/0 SSH | `configuration_change` | automatic |
| `injection` | SQL / Command / XSS injection in code | `code_change` | redeploy |
| `vulnerable_dependency` | Log4Shell, outdated npm/PyPI/Maven pkg | `dependency_upgrade` | redeploy |
| `os_vulnerability` | OpenSSL CVE in host or container | `package_upgrade` | automatic |

The 5 pinned demo issue IDs (in the Phase-1 shared Supabase):
- **8585** — public_exposure (Checkov, S3 `acme-customer-exports-prod`)
- **8586** — network_exposure (Checkov, SG `bastion-public-ssh` 0.0.0.0/0 SSH)
- **7481** — injection (SonarQube SQL injection in `checkout-service/app/views.py:193`)
- **6394** — vulnerable_dependency (OSV Log4Shell CVE-2021-44228 in `java-service`)
- **7832** — os_vulnerability (Grype OpenSSL CVE-2022-3602, container)

---

## 7. How to run it

### From the CLI (canonical way for demos and iteration)
```bash
cd apps/api

# All 5 demo issues, print + persist
uv run python scripts/run_planner.py --persist

# One specific issue, print only
uv run python scripts/run_planner.py 8585

# One specific issue, print + persist
uv run python scripts/run_planner.py 8585 --persist

# Full JSON output (for debugging schema issues)
uv run python scripts/run_planner.py --json
```

Each package takes ~30-50s with gpt-4o (5 packages ≈ 3-4 min). Cost ≈ $0.20
per full 5-package regeneration (was $0.005 with v1.2/gpt-4o-mini before we
bumped to gpt-4o for reliability).

The CLI creates one `agent_runs` row per invocation so LLM `TOKEN_USAGE`
trace events land cleanly in `agent_trace_events`.

### From the API
```bash
# Generate + persist packages for specific issues
curl -X POST http://localhost:8000/admin/remediation-packages/generate \
  -H 'content-type: application/json' \
  -d '{"issue_ids":[8585,8586,7481,6394,7832]}'

# List packages
curl http://localhost:8000/admin/remediation-packages

# Filter by status
curl 'http://localhost:8000/admin/remediation-packages?status=awaiting_approval'

# One package's full detail (includes pathways jsonb)
curl http://localhost:8000/admin/remediation-packages/1

# Approve
curl -X POST http://localhost:8000/admin/remediation-packages/1/approve \
  -H 'content-type: application/json' \
  -d '{"approved_by":"you@acmecorp.com"}'

# Reject
curl -X POST http://localhost:8000/admin/remediation-packages/1/reject \
  -H 'content-type: application/json' \
  -d '{"reason":"needs additional security review","rejected_by":"you@acmecorp.com"}'
```

Endpoints live in [`../../main.py`](../../main.py) under
`# Remediation Packages — Phase-1 §5 / §9 (Day 5)`.

### From the UI
Navigate to `/remediation` (frontend page:
[`../../../../web/src/pages/remediation.jsx`](../../../../web/src/pages/remediation.jsx)).
The page reads live from the DB and lets you Approve / Reject each package.

The header "Remediate" button (which would trigger generation from the UI) is
hidden by default — set `SHOW_REMEDIATE_BUTTON = true` in `remediation.jsx` to
expose it for iteration or demo. It's the same code path as the CLI `--persist`.

---

## 8. State machine

```
   (created via /generate or --persist)
              ↓
   status = 'awaiting_approval'
        /             \
      approve        reject
        ↓                ↓
'ready_for_execution'  'rejected'
   (terminal)         (terminal)
```

The `'draft'` state exists in the CHECK constraint as a future hook — Phase-1
never uses it (every generated package starts at `'awaiting_approval'`).

Terminal states are enforced server-side: attempting to approve a rejected
package returns 409 Conflict, and vice versa.

---

## 9. Cost + observability

Every LLM call routes through `invoke_structured_with_retry` in
[`../llm.py`](../llm.py), which fires a `TOKEN_USAGE` trace event to
`agent_trace_events` with `agent = 'sub-agent-3'`. Query it:

```sql
SELECT
  COUNT(*) AS llm_calls,
  SUM((payload->>'prompt_tokens')::int)     AS prompt_tokens,
  SUM((payload->>'completion_tokens')::int) AS completion_tokens,
  SUM((payload->>'total_tokens')::int)      AS total_tokens
FROM agent_trace_events
WHERE agent = 'sub-agent-3'
  AND (payload->>'event_subtype') = 'TOKEN_USAGE';
```

At current v1.3 settings (gpt-4o, temp 0.2, max_tokens 8000): ~5K prompt +
~3K completion per call = ~$0.04 per package. 5 packages ≈ $0.20 per full
regeneration.

Prompt is 4-5K tokens; the pattern's `canonical_steps` + `test_script_templates`
dominate the input size. Bumping to more pattern steps = larger prompt = higher
cost per call.

---

## 10. Iteration playbook

**Prompt not producing the shape we want?**
1. Update the migration file for the current version (e.g. `0044_sub_agent_3_prompt_v1_3.sql`).
2. Re-apply it in Supabase SQL Editor (idempotent — uses ON CONFLICT UPDATE).
3. Re-run: `uv run python scripts/run_planner.py --persist`
4. Diff the output. If good, done. If not, iterate. If systematically bad
   (e.g. wrong shape across all 5 packages), consider bumping model
   parameters (`fallback_model`, `max_tokens`) in the migration.

**Pattern content needs improvement?**
1. Edit the row in Supabase Table Editor OR update `0042_remediation_patterns_v2.sql`
   and re-apply.
2. `--persist` to regenerate.

**A new family emerges (e.g. `secret_leak`)?**
1. Add a rule to `classifier.py` that returns the new family string.
2. INSERT a row into `remediation_patterns` with the new family.
3. Regenerate. No LLM prompt change required — the LLM just reads whatever
   pattern lands in its payload.

**Bumping the LLM model or temperature?**
Update the `parameters` jsonb in the prompt row:
```sql
UPDATE prompt_db
SET parameters = jsonb_set(parameters, '{temperature}', '0.1')
WHERE agent = 'sub-agent-3' AND is_active = true;
```

---

## 11. What's next (Phase-2 roadmap)

Phase-1 is intentionally the "5 issues end-to-end, manual trigger, single
pathway" version. Phase-2 adds:

- **Auto-triggers**: pattern update / prompt bump / issue re-enrichment /
  asset change / scheduled refresh → auto-regenerate affected packages.
- **Sub-Agent 3 becomes a LangGraph node** in Master (currently standalone).
- **Versioned packages**: `is_current` bool + `supersedes_id` FK + latest-per-issue
  view so the operator UI shows one row per issue, audit history in the table.
- **Cost controls**: per-tenant/run budgets, idempotency caching, rate limiting,
  circuit breaker.
- **Multi-pathway per package**: for findings where multiple materially-different
  fixes exist (Log4j complete upgrade vs interim JndiLookup removal).
- **Dynamic retrieval (agentic RAG)**: fallback for unknown families — agent
  fetches vendor docs / advisories from the internet, cites URLs, optionally
  promotes results back to the static pattern catalog over time.

Total Phase-2 effort ≈ 4-6 weeks (single engineer). See the Phase-2 design
brief for the full breakdown across 5 dimensions (triggers, agent orchestration,
data versioning, cost controls, migration path).

---

## 12. Common questions

**Why is Sub-Agent 3 not in the Master pipeline?**
Cost. Wiring it to auto-run on every new issue would generate a package for all
1,860 existing issues at ~$0.04 each = ~$75 the first time. Phase-2 adds a
scope-gate ("only for THIS run's newly-enriched issues") and per-tenant budgets
before this can safely become automatic.

**Why append-only packages?**
Same principle as `issues`: preserve audit history of every regeneration
attempt. Phase-2 adds a "current view" on top so the UI isn't cluttered.

**Why 5 hand-written families instead of dynamic web retrieval?**
Deterministic + auditable + cheap. Every step traces to a citable authority in
a static row. Phase-2 adds dynamic retrieval as the long-tail fallback for
families we don't have patterns for.

**Why gpt-4o and not gpt-4o-mini?**
Prompt v1.2 on gpt-4o-mini produced structurally-wrong output on 4/5 packages
(mirroring input field names into output). Bumping to gpt-4o at v1.3 fixed it.
10× the per-call cost, but still <$0.05 per package — a rounding error for the
demo.

**Why the LLM can't invent steps?**
Hard rule in the prompt: "NEVER invent a remediation step that isn't in
pattern.canonical_steps." The prompt-plus-schema architecture makes it very
hard for the LLM to deviate. If it does invent, the source citation would be
missing (and Pydantic validation would fail).

**Where do the source citations come from?**
Every step in `remediation_patterns.canonical_steps` carries a `source` name
and `source_url`. When Sub-Agent 3 emits a step, it copies these fields
verbatim. We hand-picked them from AWS Foundational Security Best Practices,
CIS AWS Foundations Benchmark v2.0, AWS Well-Architected Security Pillar,
CISA Known Exploited Vulnerabilities Catalog, OWASP Cheat Sheets, MITRE
CWE / CAPEC / ATT&CK, NVD, and vendor advisories (Apache, OpenSSL, npm).

---

## 13. Migrations that touch this folder

Apply in order via Supabase SQL Editor:

| # | Purpose |
|---|---|
| `0036_remediation_patterns.sql` | Table + 5 seed patterns (v1) |
| `0037_sub_agent_3_prompt.sql` | Prompt v1.0 (initial) |
| `0038_extend_agent_check_for_sub_agent_3.sql` | Allow `sub-agent-3` in agent_trace_events CHECK |
| `0039_sub_agent_3_prompt_v1_1.sql` | Prompt v1.1 (pathways + structured rollback) |
| `0040_sub_agent_3_prompt_v1_1_sast_fix.sql` | Prompt v1.1 patch (SAST placeholder fix) |
| `0041_remediation_packages.sql` | Packages table + state machine |
| `0042_remediation_patterns_v2.sql` | Rich step format (Action / Command / Why) + test_script_templates column |
| `0043_sub_agent_3_prompt_v1_2.sql` | Prompt v1.2 (mandatory test_scripts, preserve rich step format) |
| `0044_sub_agent_3_prompt_v1_3.sql` | Prompt v1.3 (explicit output schema, gpt-4o) — current active |

All migrations are idempotent (ON CONFLICT UPDATE / DO $$ BEGIN ... EXCEPTION).
Safe to re-run.
