"""Sub-Agent 1 — Smart Connector (2-step pipeline: persist raw, then normalize).

Per run:
  1. Read the connector's last_fetched_at watermark from connection_registry.
  2. Fetch raw rows from the scanner (incremental).
  3. **Persist all raw rows verbatim into raw_findings.** This is the audit trail.
  4. For each persisted raw row:
       a. Call Claude (tool_use) with per-scanner prompt → LLMNormalizedIssue.
       b. Insert canonical Issue, with raw_finding_id pointing back to step 3.
  5. On success, advance the watermark.

Why split raw and canonical: replay (re-normalize without re-fetching), audit
(byte-exact what the scanner returned), separation of concerns.
"""

import json
from datetime import datetime, timezone
from typing import Any

from anthropic.types import ToolUseBlock

from ..db import supabase_admin
from ..models import LLMNormalizedIssue
from .connectors import fetch_raw_rows
from .llm import get_client
from .trace import emit_trace


# Compute the LLM tool input schema once at import time.
_NORMALIZED_ISSUE_SCHEMA = LLMNormalizedIssue.model_json_schema()


def run_fetch(run_id: str, tool: str, registry_entry: dict) -> int:
    """Read raw rows from the connector, normalize each via Claude, insert canonical Issues.

    Returns count of issues successfully inserted.
    """

    sb = supabase_admin()

    last_fetched_at = registry_entry.get("last_fetched_at")
    fetch_started_at = datetime.now(timezone.utc).isoformat()

    metadata = registry_entry.get("metadata") or {}
    connector_type = metadata.get("connector_type", "supabase_stub")

    mode = "incremental" if last_fetched_at else "initial"
    emit_trace(
        run_id, "sub-agent-1", "MESSAGE",
        f"Connecting to {tool} via connector={connector_type} "
        f"({mode}{f' — since {last_fetched_at}' if last_fetched_at else ' — fetching all rows'})",
    )

    # ------ Step 1: fetch raw rows from the connector ------
    try:
        raw_rows = fetch_raw_rows(tool, registry_entry, last_fetched_at)
    except Exception as e:
        emit_trace(
            run_id, "sub-agent-1", "ERROR",
            f"Connector failed for {tool} ({type(e).__name__}): {str(e)[:300]}",
        )
        raise

    emit_trace(
        run_id, "sub-agent-1", "MESSAGE",
        f"Fetched {len(raw_rows)} raw rows from {tool}",
    )

    if not raw_rows:
        # Still advance the watermark so the next run also looks for new rows.
        sb.table("connection_registry").update(
            {"last_fetched_at": fetch_started_at}
        ).eq("tool", tool).execute()

        emit_trace(
            run_id, "sub-agent-1", "DONE",
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
    raw_inserts = [
        {"source": tool, "agent_run_id": run_id, "raw": row}
        for row in raw_rows
    ]
    raw_insert_result = sb.table("raw_findings").insert(raw_inserts).execute()
    persisted_raws: list[dict] = raw_insert_result.data or []

    emit_trace(
        run_id, "sub-agent-1", "MESSAGE",
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
        run_id, "sub-agent-1", "MESSAGE",
        f"Loaded prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']}) "
        f"+ {len(mapping_rules)} mapping rule(s) for {tool}",
    )

    # ------ Step 3: normalize each persisted raw row -> issues ------
    inserted = 0
    failed = 0
    failure_examples: list[str] = []

    for i, persisted in enumerate(persisted_raws):
        raw_finding_id = persisted["id"]
        raw = persisted["raw"]
        try:
            llm_issue = _normalize_row(prompt_row, tool, raw, mapping_rules)
            _insert_issue(sb, llm_issue, raw_finding_id, run_id)
            inserted += 1
        except Exception as e:
            failed += 1
            if len(failure_examples) < 3:
                failure_examples.append(f"{type(e).__name__}: {e}")
                emit_trace(
                    run_id, "sub-agent-1", "ERROR",
                    f"Row {i} failed ({type(e).__name__}): {str(e)[:400]}",
                    payload={
                        "row_index": i,
                        "raw_finding_id": raw_finding_id,
                        "exception_type": type(e).__name__,
                        "exception_message": str(e)[:1000],
                    },
                )

        if (i + 1) % 20 == 0 and (i + 1) < len(persisted_raws):
            emit_trace(
                run_id, "sub-agent-1", "MESSAGE",
                f"Processed {i + 1}/{len(persisted_raws)} rows "
                f"({inserted} succeeded, {failed} failed so far)",
            )

    if failed:
        emit_trace(
            run_id, "sub-agent-1", "MESSAGE",
            f"Completed normalization: {inserted} succeeded, {failed} failed. "
            f"Examples: {'; '.join(failure_examples)}",
        )
    else:
        emit_trace(
            run_id, "sub-agent-1", "MESSAGE",
            f"Completed normalization: {inserted}/{len(persisted_raws)} rows normalized cleanly",
        )

    # Advance watermark so the next run only fetches rows created after this point.
    # Only do this if we successfully processed at least some rows — if the entire
    # batch failed, leave the watermark alone so a retry sees the same data.
    if inserted > 0:
        sb.table("connection_registry").update(
            {"last_fetched_at": fetch_started_at}
        ).eq("tool", tool).execute()

    emit_trace(
        run_id, "sub-agent-1", "DONE",
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
    """Call Claude with tool_use to normalize one raw row to a canonical Issue.

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

    response = client.messages.create(
        model=prompt_row["model"],
        max_tokens=int(params.get("max_tokens", 2000)),
        temperature=float(params.get("temperature", 0.1)),
        system=[
            {
                "type": "text",
                "text": prompt_row["prompt_text"],
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=[
            {
                "name": "emit_canonical_issue",
                "description": (
                    "Emit one normalized canonical Issue produced from a single raw scanner row. "
                    "Call this exactly once per row, with the normalized fields populated."
                ),
                "input_schema": _NORMALIZED_ISSUE_SCHEMA,
            }
        ],
        tool_choice={"type": "tool", "name": "emit_canonical_issue"},
        messages=[{"role": "user", "content": user_message}],
    )

    tool_block = next(
        (b for b in response.content if isinstance(b, ToolUseBlock)), None
    )
    if tool_block is None:
        raise ValueError("LLM did not call the emit_canonical_issue tool")

    return LLMNormalizedIssue(**tool_block.input)


def _insert_issue(
    sb, llm_issue: LLMNormalizedIssue, raw_finding_id: int, run_id: str
) -> None:
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
        "first_detected": llm_issue.first_detected.isoformat() if llm_issue.first_detected else None,
        "raw_finding_id": raw_finding_id,
        "agent_run_id": run_id,
    }
    sb.table("issues").insert(row).execute()
