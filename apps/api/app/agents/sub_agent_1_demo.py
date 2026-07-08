"""Sub-Agent 1 — DEMO orchestrator.

Reuses the pure normalization + CVSS helpers from `sub_agent_1.py` but
orchestrates against the `demo` Postgres schema:

  Input:   demo.raw_findings (pre-loaded fixture; migration 0046 seeds 5 rows)
  Output:  demo.issues       (LLM-normalized canonical rows)
  Config:  public.prompt_db + public.schema_mapping (shared with real pipeline)
  Trace:   demo.agent_trace_events + demo.agent_runs (via trace_demo)

No connector call — demo raws are pre-seeded, so we skip the fetch step
entirely. This is the "run pipeline against the 5 pinned demo IDs" entry
point that master_demo.py drives.

See [[agentic-vop-demo-pipeline-architecture]] for why this file exists
instead of a `demo=True` branch inside `sub_agent_1.py`.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ..config import settings
from ..db import supabase_admin, supabase_admin_demo
from ..models import LLMNormalizedIssue
from .llm import invoke_structured_with_retry
from .sub_agent_1 import (
    _sanitize,
    extract_all_vectors_from_raw,
    parse_cvss_vector,
    pick_best_cvss_vector,
)
from .trace_demo import RunCancelledError, emit_trace_demo, is_cancellation_requested_demo


def run_demo_fetch(run_id: str) -> tuple[int, dict]:
    """Normalize the pre-seeded rows in demo.raw_findings into demo.issues.

    Returns (count of issues inserted, token_totals dict).

    Skips the connector step entirely — the fixture in demo.raw_findings is
    the input. Everything else mirrors sub_agent_1.run_fetch (same LLM prompt,
    same schema-mapping rules, same CVSS post-processing, same parallel
    worker pattern).
    """
    sb_demo = supabase_admin_demo()
    sb_pub = supabase_admin()  # for prompt_db + schema_mapping (shared config)

    emit_trace_demo(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        "Demo pipeline: reading pre-seeded raws from demo.raw_findings",
    )

    persisted_raws: list[dict] = (
        sb_demo.table("raw_findings")
        .select("id, source, raw")
        .order("id")
        .execute()
        .data
        or []
    )

    if not persisted_raws:
        emit_trace_demo(
            run_id,
            "sub-agent-1",
            "DONE",
            "FETCH_DONE — demo.raw_findings is empty (nothing to normalize)",
            payload={
                "from": "sub-agent-1",
                "status": "FETCH_DONE",
                "scan_id": run_id,
                "records_persisted": 0,
                "records_normalized": 0,
            },
        )
        return 0, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    emit_trace_demo(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Loaded {len(persisted_raws)} pre-seeded raw rows from demo.raw_findings",
    )

    # Prompt loading: shared with real pipeline (public.prompt_db).
    prompt_row = (
        sb_pub.table("prompt_db")
        .select("*")
        .eq("agent", "sub-agent-1")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    # Mapping rules: also shared. Grouped by scanner so we look them up once.
    scanners_present = sorted({r["source"] for r in persisted_raws})
    mapping_rules_by_tool: dict[str, list[dict]] = {}
    for tool in scanners_present:
        mapping_rules_by_tool[tool] = (
            sb_pub.table("schema_mapping")
            .select("source_field,canonical_field,transform,notes")
            .eq("scanner", tool)
            .execute()
            .data
            or []
        )

    emit_trace_demo(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Loaded prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']}) "
        f"+ mapping rules for {len(scanners_present)} scanner(s)",
    )

    # ---- Normalize + insert (parallel workers, same pattern as real) ----
    inserted = 0
    failed = 0
    failure_examples: list[str] = []

    workers = max(1, int(settings.llm_parallel_workers or 10))
    emit_trace_demo(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Normalizing {len(persisted_raws)} row(s)…",
    )

    def _process_one(persisted: dict) -> dict:
        if is_cancellation_requested_demo(run_id):
            raise RunCancelledError(f"Skipping row {persisted['id']} — run cancelled")
        raw_finding_id = persisted["id"]
        tool = persisted["source"]
        raw = persisted["raw"]
        llm_issue = _normalize_row_demo(run_id, prompt_row, tool, raw, mapping_rules_by_tool[tool])
        llm_issue.source = tool
        # CVSS resolution — same helpers as real path.
        candidate_vectors = extract_all_vectors_from_raw(raw)
        if llm_issue.cvss_vector:
            candidate_vectors.append(llm_issue.cvss_vector)
        best_vector = pick_best_cvss_vector(candidate_vectors)
        if best_vector:
            llm_issue.cvss_vector = best_vector
        if llm_issue.cvss_vector and (
            llm_issue.cvss_score is None or llm_issue.cvss_version is None
        ):
            score, version = parse_cvss_vector(llm_issue.cvss_vector)
            if score is not None and llm_issue.cvss_score is None:
                llm_issue.cvss_score = score
            if version is not None and llm_issue.cvss_version is None:
                llm_issue.cvss_version = version
        _insert_issue_demo(sb_demo, llm_issue, raw_finding_id, run_id)
        return {"raw_finding_id": raw_finding_id}

    cancelled = False
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_process_one, p): p for p in persisted_raws}
        for future in as_completed(futures):
            persisted = futures[future]
            try:
                future.result()
                inserted += 1
            except RunCancelledError:
                cancelled = True
            except Exception as e:
                failed += 1
                if len(failure_examples) < 3:
                    failure_examples.append(f"{type(e).__name__}: {e}")
                    emit_trace_demo(
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

    if cancelled:
        emit_trace_demo(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"Cancellation detected — stopped after {inserted} normalized row(s)",
        )
        raise RunCancelledError("Sub-Agent 1 (demo) stopped due to user cancellation")

    emit_trace_demo(
        run_id,
        "sub-agent-1",
        "DONE",
        f"FETCH_DONE — {len(persisted_raws)} raw / {inserted} canonical",
        payload={
            "from": "sub-agent-1",
            "status": "FETCH_DONE",
            "scan_id": run_id,
            "records_persisted": len(persisted_raws),
            "records_normalized": inserted,
            "records_failed": failed,
        },
    )

    # Aggregate tokens from trace events (mirrors real path).
    token_events = (
        sb_demo.table("agent_trace_events")
        .select("payload")
        .eq("run_id", run_id)
        .eq("agent", "sub-agent-1")
        .execute()
        .data
        or []
    )
    total_prompt = total_completion = total_tokens_sum = 0
    for event in token_events:
        payload = event.get("payload") or {}
        if payload.get("event_subtype") == "TOKEN_USAGE":
            total_prompt += payload.get("prompt_tokens", 0)
            total_completion += payload.get("completion_tokens", 0)
            total_tokens_sum += payload.get("total_tokens", 0)

    return inserted, {
        "prompt_tokens": total_prompt,
        "completion_tokens": total_completion,
        "total_tokens": total_tokens_sum,
    }


def _normalize_row_demo(
    run_id: str,
    prompt_row: dict,
    tool: str,
    raw_row: dict,
    mapping_rules: list[dict],
) -> LLMNormalizedIssue:
    """Call ChatOpenAI with structured output — same shape as sub_agent_1._normalize_row.

    Kept as a demo-local copy (rather than importing from sub_agent_1) because
    the real function is module-private and re-importing crosses the
    real/demo boundary we're trying to keep clean.
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
        emit_fn=emit_trace_demo,
    )


def _insert_issue_demo(
    sb_demo, llm_issue: LLMNormalizedIssue, raw_finding_id: int, run_id: str
) -> None:
    """Insert one canonical Issue into demo.issues."""
    row: dict[str, Any] = {
        "source": llm_issue.source,
        "source_vuln_id": llm_issue.source_vuln_id,
        "cve_id": llm_issue.cve_id,
        "all_cves": llm_issue.all_cves,
        "cwe_id": llm_issue.cwe_id,
        "title": llm_issue.title,
        "description": llm_issue.description,
        "severity": llm_issue.severity,
        "cvss_score": llm_issue.cvss_score,
        "cvss_version": llm_issue.cvss_version,
        "cvss_vector": llm_issue.cvss_vector,
        "solution": llm_issue.solution,
        "asset_identity": llm_issue.asset_identity,
        "package": llm_issue.package,
        "first_detected": llm_issue.first_detected.isoformat()
        if llm_issue.first_detected
        else None,
        "raw_finding_id": raw_finding_id,
        "agent_run_id": run_id,
    }
    sb_demo.table("issues").insert(_sanitize(row)).execute()
