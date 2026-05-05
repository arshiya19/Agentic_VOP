"""Sub-Agent 1 — Smart Connector (2-step pipeline: persist raw, then normalize).

Per run:
  1. Read the connector's last_fetched_at watermark from connection_registry.
  2. Fetch raw rows from the scanner (incremental).
  3. **Persist all raw rows verbatim into raw_findings.** This is the audit trail.
  4. For each persisted raw row:
       a. Call the LLM (function calling) with per-scanner prompt → LLMNormalizedIssue.
       b. Insert canonical Issue, with raw_finding_id pointing back to step 3.
  5. On success, advance the watermark.

Why split raw and canonical: replay (re-normalize without re-fetching), audit
(byte-exact what the scanner returned), separation of concerns.
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from ..config import settings
from ..db import supabase_admin
from ..models import LLMNormalizedIssue
from .connectors import fetch_raw_rows
from .llm import get_client
from .trace import emit_trace


# Compute the LLM tool input schema once at import time.
_NORMALIZED_ISSUE_SCHEMA = LLMNormalizedIssue.model_json_schema()

# Matches a \u that isn't followed by exactly 4 hex digits — i.e., a malformed
# Unicode escape. The LLM emits these very rarely; one bad row would otherwise
# drop the whole call.
_BAD_UNICODE_ESCAPE = re.compile(r"\\u(?![0-9a-fA-F]{4})")
_ANY_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{0,4}")


def _parse_function_args(args_str: str) -> dict:
    """json.loads with multi-stage repair for the malformed \\u escapes the LLM
    occasionally produces. Tries: (1) as-is, (2) replace bad \\u with safe \\u0020
    (a space), (3) strip every \\u escape as a last resort.
    """
    try:
        return json.loads(args_str)
    except json.JSONDecodeError:
        pass
    try:
        # Replace each bad \u with a safe escape for SPACE (\u0020) — preserves
        # string structure better than just deleting the \u.
        return json.loads(_BAD_UNICODE_ESCAPE.sub(r"\\u0020", args_str))
    except json.JSONDecodeError:
        pass
    # Last-resort: drop every \u sequence entirely. Loses some characters but
    # the row still goes through.
    return json.loads(_ANY_UNICODE_ESCAPE.sub("", args_str))


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


def run_fetch(run_id: str, tool: str, registry_entry: dict) -> int:
    """Read raw rows from the connector, normalize each via the LLM, insert canonical Issues.

    Returns count of issues successfully inserted.
    """

    sb = supabase_admin()

    last_fetched_at = registry_entry.get("last_fetched_at")
    fetch_started_at = datetime.now(datetime.UTC).isoformat()

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
        raw_rows = fetch_raw_rows(tool, registry_entry, last_fetched_at)
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
        return 0

    # ------ Step 2: persist raw rows verbatim into raw_findings ------
    # Sanitize NUL bytes (\u0000) — Postgres' text/jsonb types reject them.
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
        llm_issue = _normalize_row(prompt_row, tool, raw, mapping_rules)
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
    return inserted


def _normalize_row(
    prompt_row: dict,
    tool: str,
    raw_row: dict,
    mapping_rules: list[dict],
) -> LLMNormalizedIssue:
    """Call OpenAI with function calling to normalize one raw row to a canonical Issue.

    The LLM receives:
      - source_scanner (tool name, e.g., "osv")
      - raw_row (the scanner's raw output)
      - mapping_rules (per-scanner translation rules from schema_mapping)
    """
    client = get_client()

    user_message = json.dumps(
        {
            "source_scanner": tool,
            "raw_row": raw_row,
            "mapping_rules": mapping_rules,
        },
        default=str,
    )

    params = prompt_row.get("parameters") or {}

    base_temp = float(params.get("temperature", 0.1))

    def _build_kwargs(temperature: float) -> dict:
        return dict(
            model=prompt_row["model"],
            max_tokens=int(params.get("max_tokens", 2000)),
            temperature=temperature,
            messages=[
                {"role": "system", "content": prompt_row["prompt_text"]},
                {"role": "user", "content": user_message},
            ],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "emit_canonical_issue",
                        "description": (
                            "Emit one normalized canonical Issue produced from a single raw scanner row. "
                            "Call this exactly once per row, with the normalized fields populated."
                        ),
                        "parameters": _NORMALIZED_ISSUE_SCHEMA,
                    },
                }
            ],
            tool_choice={"type": "function", "function": {"name": "emit_canonical_issue"}},
        )

    # Up to 3 attempts: first at low temp, retries at higher temp so the LLM
    # samples differently and breaks out of any deterministic bad-output loop.
    attempts = [base_temp, 0.6, 0.9]
    last_err: Exception | None = None
    for temperature in attempts:
        try:
            response = client.chat.completions.create(**_build_kwargs(temperature))
            tool_calls = response.choices[0].message.tool_calls or []
            if not tool_calls:
                raise ValueError("LLM did not call the emit_canonical_issue function")
            parsed = _parse_function_args(tool_calls[0].function.arguments)
            return LLMNormalizedIssue(**parsed)
        except Exception as e:  # noqa: BLE001
            last_err = e
    assert last_err is not None  # nosec B101 — type narrowing only; loop always sets last_err before this line
    raise last_err


def _insert_issue(sb, llm_issue: LLMNormalizedIssue, raw_finding_id: int, run_id: str) -> None:
    """Insert one new canonical Issue. Points back to the raw_findings row by FK."""
    row: dict[str, Any] = {
        "source": llm_issue.source,
        "source_vuln_id": llm_issue.source_vuln_id,
        "cve_id": llm_issue.cve_id,
        "all_cves": llm_issue.all_cves,
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
