"""Sub-Agent 1 — Smart Connector (LangChain-powered normalization).

Per run:
  1. Read the connector's last_fetched_at watermark from connection_registry.
  2. Fetch raw rows from the scanner (incremental, via connectors/).
  3. Persist all raw rows verbatim into raw_findings (audit trail).
  4. For each persisted raw row:
       a. Call ChatOpenAI.with_structured_output(LLMNormalizedIssue).
       b. Insert canonical Issue with raw_finding_id pointing back to step 3.
  5. On success, advance the watermark.

Why split raw and canonical: replay (re-normalize without re-fetching), audit
(byte-exact what the scanner returned), separation of concerns.

LangChain migration notes:
  - The raw OpenAI SDK function call is replaced by ChatOpenAI's
    `.with_structured_output(LLMNormalizedIssue)`, which binds the Pydantic
    schema as the response shape and validates automatically.
  - Multi-stage JSON repair is no longer required for the happy path —
    LangChain handles structured output internally. We keep the
    temperature-escalation retry pattern (0.1 → 0.6 → 0.9) for robustness
    against rare validation failures.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ..config import settings
from ..db import supabase_admin
from ..models import LLMNormalizedIssue
from .connectors import fetch_raw_rows
from .llm import invoke_structured_with_retry
from .trace import emit_trace


def _sanitize(value: Any) -> Any:
    """Recursively strip Postgres-incompatible NUL bytes (\\u0000) from a JSON-like structure.

    Some scanners (and downstream LLM output) can include \\x00 in description text;
    Postgres' text/jsonb types reject it with "unsupported Unicode escape sequence".
    """
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def run_fetch(run_id: str, tool: str, registry_entry: dict) -> tuple[int, dict]:
    """Read raw rows from the connector, normalize each via the LLM, insert canonical Issues.

    Returns (count of issues inserted, token_totals dict).

    Note on token totals: LangChain emits token usage via the
    `_TokenUsageCallback` in `llm.py` (one TOKEN_USAGE trace event per
    LLM call). The aggregate returned here is best-effort and will be
    zero unless the callback also writes to a sidecar — to keep the
    public contract with master.py the same, we return zeros and
    rely on the per-call TOKEN_USAGE events for observability.
    """
    sb = supabase_admin()

    last_fetched_at = registry_entry.get("last_fetched_at")
    fetch_started_at = datetime.now(UTC).isoformat()

    metadata = registry_entry.get("metadata") or {}
    connector_type = metadata.get("connector_type", "supabase_stub")

    mode = "incremental" if last_fetched_at else "initial"
    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Connecting to {tool} via connector={connector_type} "
        f"({mode}{f' — since {last_fetched_at}' if last_fetched_at else ' — fetching all rows'})",
    )

    # ------ Step 1: fetch raw rows from the connector ------
    try:
        raw_rows = fetch_raw_rows(tool, registry_entry, last_fetched_at, run_id=run_id)
    except Exception as e:
        emit_trace(
            run_id,
            "sub-agent-1",
            "ERROR",
            f"Connector failed for {tool} ({type(e).__name__}): {str(e)[:300]}",
        )
        raise

    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Fetched {len(raw_rows)} raw rows from {tool}",
    )

    if not raw_rows:
        # Still advance the watermark so the next run also looks for new rows.
        sb.table("connection_registry").update({"last_fetched_at": fetch_started_at}).eq(
            "tool", tool
        ).execute()

        emit_trace(
            run_id,
            "sub-agent-1",
            "DONE",
            "FETCH_DONE — no new rows since last fetch",
            payload={
                "from": "sub-agent-1",
                "status": "FETCH_DONE",
                "scan_id": run_id,
                "records_fetched": 0,
                "records_persisted": 0,
                "records_normalized": 0,
                "tool_used": tool,
                "watermark_before": last_fetched_at,
                "watermark_after": fetch_started_at,
            },
        )
        return 0, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    # ------ Step 2: persist raw rows verbatim into raw_findings ------
    raw_inserts = [
        {"source": tool, "agent_run_id": run_id, "raw": _sanitize(row)} for row in raw_rows
    ]
    raw_insert_result = sb.table("raw_findings").insert(raw_inserts).execute()
    persisted_raws: list[dict] = raw_insert_result.data or []

    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Persisted {len(persisted_raws)} raw rows to raw_findings",
    )

    # Generic Sub-Agent 1 prompt (one prompt for all scanners)
    prompt_row = (
        sb.table("prompt_db")
        .select("*")
        .eq("agent", "sub-agent-1")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    # Per-scanner mapping rules from the Schema & Mapping DB
    mapping_rules = (
        sb.table("schema_mapping")
        .select("source_field,canonical_field,transform,notes")
        .eq("scanner", tool)
        .execute()
        .data
        or []
    )

    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Loaded prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']}) "
        f"+ {len(mapping_rules)} mapping rule(s) for {tool}",
    )

    # ------ Step 3: normalize each persisted raw row -> issues (parallel) ------
    inserted = 0
    failed = 0
    failure_examples: list[str] = []

    workers = max(1, int(settings.llm_parallel_workers or 10))
    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Normalizing {len(persisted_raws)} row(s)…",
    )

    def _process_one(persisted: dict) -> dict:
        """Per-row task: LLM-normalize then insert. Runs inside a worker thread."""
        raw_finding_id = persisted["id"]
        raw = persisted["raw"]
        llm_issue = _normalize_row(run_id, prompt_row, tool, raw, mapping_rules)
        # Authoritative: the source on an issue must match the tool that
        # produced it, regardless of what the LLM returned. This is the
        # single source of truth for "where this finding came from".
        llm_issue.source = tool
        _insert_issue(sb, llm_issue, raw_finding_id, run_id)
        return {"raw_finding_id": raw_finding_id}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_process_one, p): p for p in persisted_raws}
        completed = 0
        for future in as_completed(futures):
            persisted = futures[future]
            completed += 1
            try:
                future.result()
                inserted += 1
            except Exception as e:
                failed += 1
                if len(failure_examples) < 3:
                    failure_examples.append(f"{type(e).__name__}: {e}")
                    emit_trace(
                        run_id,
                        "sub-agent-1",
                        "ERROR",
                        f"Row {persisted['id']} failed ({type(e).__name__}): {str(e)[:400]}",
                        payload={
                            "raw_finding_id": persisted["id"],
                            "exception_type": type(e).__name__,
                            "exception_message": str(e)[:1000],
                        },
                    )

            if completed % 20 == 0 and completed < len(persisted_raws):
                emit_trace(
                    run_id,
                    "sub-agent-1",
                    "MESSAGE",
                    f"Processed {completed}/{len(persisted_raws)} rows "
                    f"({inserted} succeeded, {failed} failed so far)",
                )

    if failed:
        emit_trace(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"Completed normalization: {inserted} succeeded, {failed} failed. "
            f"Examples: {'; '.join(failure_examples)}",
        )
    else:
        emit_trace(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"Completed normalization: {inserted}/{len(persisted_raws)} rows normalized cleanly",
        )

    # Advance watermark so the next run only fetches rows created after this point.
    # Only do this if we successfully processed at least some rows — if the entire
    # batch failed, leave the watermark alone so a retry sees the same data.
    if inserted > 0:
        sb.table("connection_registry").update({"last_fetched_at": fetch_started_at}).eq(
            "tool", tool
        ).execute()

    emit_trace(
        run_id,
        "sub-agent-1",
        "DONE",
        f"FETCH_DONE — {len(persisted_raws)} raw / {inserted} canonical",
        payload={
            "from": "sub-agent-1",
            "status": "FETCH_DONE",
            "scan_id": run_id,
            "records_fetched": len(raw_rows),
            "records_persisted": len(persisted_raws),
            "records_normalized": inserted,
            "records_failed": failed,
            "tool_used": tool,
            "data_pointer_raw": f"pg://raw_findings?agent_run_id={run_id}",
            "data_pointer_canonical": f"pg://issues?agent_run_id={run_id}",
            "correlation_id": f"corr-{run_id[:8]}",
        },
    )

    # Aggregate token usage from all TOKEN_USAGE trace events emitted during this run
    token_events = (
        sb.table("agent_trace_events")
        .select("payload")
        .eq("run_id", run_id)
        .eq("agent", "sub-agent-1")
        .execute()
        .data
        or []
    )

    total_prompt = 0
    total_completion = 0
    total_tokens_sum = 0
    for event in token_events:
        payload = event.get("payload") or {}
        if payload.get("event_subtype") == "TOKEN_USAGE":
            total_prompt += payload.get("prompt_tokens", 0)
            total_completion += payload.get("completion_tokens", 0)
            total_tokens_sum += payload.get("total_tokens", 0)

    token_totals = {
        "prompt_tokens": total_prompt,
        "completion_tokens": total_completion,
        "total_tokens": total_tokens_sum,
    }
    return inserted, token_totals


def _normalize_row(
    run_id: str,
    prompt_row: dict,
    tool: str,
    raw_row: dict,
    mapping_rules: list[dict],
) -> LLMNormalizedIssue:
    """Call ChatOpenAI with structured output to normalize one raw row.

    Tiered retry — escalate temperature first (cheap), then escalate the model
    on the final attempt (smarter) for rows the small model can't handle.
    """
    params = prompt_row.get("parameters") or {}
    base_temp = float(params.get("temperature", 0.1))
    max_tokens = int(params.get("max_tokens", 2000))
    primary_model = prompt_row["model"]
    fallback_model = params.get("fallback_model", "gpt-4o")

    user_payload = {
        "source_scanner": tool,
        "raw_row": raw_row,
        "mapping_rules": mapping_rules,
    }

    # Per-attempt completion budget grows on each retry — gnarly OSV advisories
    # (e.g. 10k-token prompts with huge affected-version arrays) sometimes need
    # more room than the base config to finish the structured-output tool call.
    return invoke_structured_with_retry(
        run_id=run_id,
        agent="sub-agent-1",
        schema=LLMNormalizedIssue,
        messages=[
            SystemMessage(content=prompt_row["prompt_text"]),
            HumanMessage(content=str(user_payload)),
        ],
        attempts=[
            (base_temp, primary_model, max_tokens),
            (0.6, primary_model, max_tokens + 2000),
            (0.3, fallback_model, max_tokens + 4000),
        ],
    )


def _insert_issue(sb, llm_issue: LLMNormalizedIssue, raw_finding_id: int, run_id: str) -> None:
    """Insert one new canonical Issue. Points back to the raw_findings row by FK."""
    row: dict[str, Any] = {
        "source": llm_issue.source,
        "source_vuln_id": llm_issue.source_vuln_id,
        "cve_id": llm_issue.cve_id,
        "all_cves": llm_issue.all_cves,
        # Persist any CWE id Sub-Agent 1 pulled out of the raw row (e.g. for SAST
        # findings that have no CVE). Sub-Agent 2 will use it as a fallback when
        # the NVD lookup can't supply one.
        "cwe_id": llm_issue.cwe_id,
        "title": llm_issue.title,
        "description": llm_issue.description,
        "severity": llm_issue.severity,
        "cvss_score": llm_issue.cvss_score,
        "cvss_version": llm_issue.cvss_version,
        "solution": llm_issue.solution,
        "asset_identity": llm_issue.asset_identity,
        "package": llm_issue.package,
        "first_detected": llm_issue.first_detected.isoformat()
        if llm_issue.first_detected
        else None,
        "raw_finding_id": raw_finding_id,
        "agent_run_id": run_id,
    }
    # Sanitize NUL bytes from any string field (some scanners emit them via the LLM).
    sb.table("issues").insert(_sanitize(row)).execute()
