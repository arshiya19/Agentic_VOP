"""Master — DEMO orchestrator.

LangGraph shape:
  START → load_context → sample → enrich → remediate → fix → summarize → END

The demo pipeline seeds `demo.issues` by SAMPLING 1 issue per family from
real -ec2 issues in `public.issues` (see sample_from_real.py). Enrichment,
remediation (SA3), and execution (SA4) then run against those copied rows,
isolated in demo schema.

Differences vs real master.py:
  - No planning step — fixed sequence, no LLM plan needed.
  - No FETCH step — real fetch already ran and populated public.issues with
    -ec2 sources; the demo just samples from those.
  - Adds a REMEDIATE step (via planner_demo) after enrichment.
  - Adds a FIX step (Sub-Agent 4) after remediation — auto-chained per
    settings.fixer_auto_chain. Runs against env2 via SSM RunCommand.
  - All state reads/writes go through demo.* (via supabase_admin_demo()).

Run entry: run_demo_master(run_id) — mirrors run_master().
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from ..config import settings
from ..db import supabase_admin_demo
from .remediation import planner_demo
from .sample_from_real import sample_and_copy_ec2_issues
from .sub_agent_2_demo import run_demo_enrich
from .trace_demo import RunCancelledError, emit_trace_demo, is_cancellation_requested_demo


# Regex helpers for honest per-check counting. A rescan is either NARROW
# (filters to a specific check_id / rule_id) or BROAD (runs the whole
# scanner and asserts zero total findings). Only NARROW rescans can be
# credited to a specific finding; BROAD rescans credit all findings in the
# batch when they pass. Everything else (a rescan that doesn't fit either
# shape) is treated conservatively as NARROW-with-unknown-target and does
# not credit any specific finding beyond 1.
_NARROW_CHECK_FLAG = re.compile(r"--check(?:-id)?[\s=]+([A-Za-z0-9_.\-/]+)")
_NARROW_GREP = re.compile(r"grep\s+-c\s+['\"]([A-Za-z0-9_.\-/:]+)['\"]")
# Broad-rescan signal: no --check filter AND no grep-for-specific-id.
# Presence of `failed_checks": []` or `"failed": 0` in the command (or
# expected) indicates whole-file assertion.
_BROAD_ASSERT = re.compile(r'failed(?:_checks)?["\']?\s*[:=]\s*(?:\[\s*\]|0)')


def _rescan_covers_check_ids(cmd: str, expected: str = "") -> tuple[set[str], bool]:
    """Inspect a rescan command and return (narrow_check_ids, is_broad).

    - narrow_check_ids: set of check_id / rule_id strings the command
      explicitly filters to. Empty set if none detected.
    - is_broad: True if the command asserts absence of ALL findings on the
      target (whole-file scan without narrowing, expecting zero total).

    Both can be non-empty simultaneously — a command that runs the scanner
    with --check X AND asserts zero total counts as narrow to X.
    """
    text = (cmd or "") + " " + (expected or "")
    narrow: set[str] = set()
    narrow.update(_NARROW_CHECK_FLAG.findall(text))
    narrow.update(_NARROW_GREP.findall(text))
    is_broad = bool(_BROAD_ASSERT.search(text)) and not narrow
    return narrow, is_broad


class DemoMasterState(TypedDict, total=False):
    run_id: str
    # ID of the linked real agent_run whose -ec2 output feeds sampling.
    # Optional — None means "sample across all -ec2 issues in the DB."
    real_run_id: str | None
    sample_result: dict
    enrich_result: dict
    remediation_result: dict
    fix_result: dict
    error_message: str | None


def _load_context_node(state: DemoMasterState) -> dict:
    """Mark demo run as running, emit start trace."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    # The agent_runs row is created by the endpoint before graph invoke,
    # so this only flips status. If it doesn't exist yet, still emit trace.
    sb.table("agent_runs").update({"status": "running"}).eq("run_id", run_id).execute()

    emit_trace_demo(
        run_id,
        "master",
        "DISPATCH",
        "Demo pipeline started: sample -ec2 → remediate → fix (enrichment skipped — already done in real pipeline)",
    )
    return {
        "sample_result": {},
        "enrich_result": {},
        "remediation_result": {},
        "fix_result": {},
    }


def _sample_node(state: DemoMasterState) -> dict:
    """Sample 1 real -ec2 issue per family and copy into demo.issues.

    If state.real_run_id is set, only samples from that specific real fetch's
    output — prevents pulling in unrelated stale -ec2 rows.
    """
    run_id = state["run_id"]
    real_run_id = state.get("real_run_id")
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before sampling")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sample-from-real")
    result = sample_and_copy_ec2_issues(run_id, real_run_id=real_run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received SAMPLE_DONE — {result.get('sampled', 0)} real -ec2 issue(s) "
        f"copied into demo.issues (families found: {result.get('families_found', [])})",
    )
    return {"sample_result": result}


def _enrich_node(state: DemoMasterState) -> dict:
    """Sub-Agent 2 demo — enrich the demo issues."""
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before enrichment")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sub-Agent 2 (demo)")
    result = run_demo_enrich(run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received ENRICH_DONE — {result.get('enriched', 0)} issue(s) enriched "
        f"(EPSS: {result.get('epss_hits', 0)}, "
        f"KEV: {result.get('kev_hits', 0)}, "
        f"NVD: {result.get('nvd_hits', 0)})",
    )
    return {"enrich_result": result}


def _remediate_node(state: DemoMasterState) -> dict:
    """Sub-Agent 3 demo — generate + persist RemediationPackages."""
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before remediation")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sub-Agent 3 (demo)")
    result = planner_demo.run_demo_remediation(run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received REMEDIATE_DONE — {result.get('persisted', 0)} package(s) persisted",
    )
    return {"remediation_result": result}


def _fix_node(state: DemoMasterState) -> dict:
    """Sub-Agent 4 demo — auto-chained execution of every persisted package.

    Runs the fixer once per remediation_package created by this demo run.
    Sequential (one at a time) because env2 + terraform state can't be
    raced in parallel — see FixerConfig.allow_concurrent_runs.

    Two config toggles govern behavior:
      settings.fixer_auto_chain      — when False, skip the fixer entirely
                                        (useful pre-env2 provisioning)
      settings.fixer_env2_instance_id — when empty, skip + emit a warning
                                        (fail-soft, don't halt demo)
    """
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before fix stage")

    # Toggle 1 — auto-chain off?
    if not settings.fixer_auto_chain:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — settings.fixer_auto_chain is False",
        )
        return {"fix_result": {"skipped": True, "reason": "auto_chain_disabled"}}

    # Toggle 2 — no env2 configured?
    if not settings.fixer_env2_instance_id:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — FIXER_ENV2_INSTANCE_ID not set (env2 not provisioned yet)",
        )
        return {"fix_result": {"skipped": True, "reason": "env2_not_configured"}}

    # Load packages this demo run just persisted
    sb = supabase_admin_demo()
    pkg_rows = (
        sb.table("remediation_packages")
        # `pathways` needed so we can read the per-batch covered_issue_ids
        # marker persisted in pathway.considerations for findings-level counts.
        .select("id, family, issue_id, pathways")
        .eq("agent_run_id", run_id)
        .execute()
        .data
        or []
    )

    if not pkg_rows:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — no packages to fix (upstream stage produced none)",
        )
        return {"fix_result": {"skipped": True, "reason": "no_packages"}}

    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Dispatching to Sub-Agent 4 (demo) — {len(pkg_rows)} package(s) to fix on env2",
    )

    # Import lazily so the demo module doesn't force the SA4 dependency graph
    # to import at module-load time (kept the fixer package light for tests).
    from .fixer import run_fixer  # noqa: PLC0415

    fix_runs: list[dict] = []
    succeeded = 0
    partial = 0
    no_fix_needed_count = 0
    failed = 0
    rolled_back = 0
    # Findings-level counts — one package may cover multiple findings when
    # per-file batching kicks in.
    findings_covered = 0
    findings_fixed = 0
    findings_remain = 0
    # findings_no_fix_needed: file is already clean OR KB adapter's literals
    # didn't match this file. Not counted as fixed (we did nothing) and not
    # as remaining (validation passed) — third bucket for honest reporting.
    findings_no_fix_needed = 0
    # findings_unaddressed: package ran successfully AND validation passed,
    # BUT the passing re-scans only cover K < pkg_findings distinct check_ids.
    # The un-rescanned findings can't honestly be credited as fixed — they
    # go here. This prevents SA-3 under-emitting from inflating the fixed count.
    findings_unaddressed = 0

    for pkg in pkg_rows:
        if is_cancellation_requested_demo(run_id):
            raise RunCancelledError("Demo run cancelled during fix stage")

        # How many findings did this package cover?
        # Batched packages persist their `__batch_covered_ids__:1,2,3` marker
        # inside pathways[0].considerations. Singleton packages omit the
        # marker → default to 1 finding.
        pkg_findings = 1
        try:
            pathways = pkg.get("pathways") or []
            for pathway in pathways:
                for note in pathway.get("considerations") or []:
                    if isinstance(note, str) and note.startswith("__batch_covered_ids__:"):
                        ids_str = note.split(":", 1)[1]
                        pkg_findings = len([x for x in ids_str.split(",") if x.strip()])
                        break
                if pkg_findings > 1:
                    break
        except Exception:  # noqa: BLE001, S110
            pass

        try:
            fix_run_id = run_fixer(
                pkg["id"],
                agent_run_id=run_id,
                sb=sb,
                emit_fn=emit_trace_demo,
                environment="sandbox",
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "master",
                "ERROR",
                f"Sub-Agent 4 dispatch failed for package #{pkg['id']}: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )
            failed += 1
            findings_covered += pkg_findings
            findings_remain += pkg_findings
            fix_runs.append({"package_id": pkg["id"], "status": "dispatch_failed"})
            continue

        # Read back final status + validation + step results.
        # step_results is needed to detect "no_fix_needed" — when 0 structured
        # edits actually applied but validation passed anyway (the phantom-
        # success case caused by KB adapter blind-copying literals).
        row = (
            sb.table("fix_runs")
            .select("id, status, validation_results, step_results")
            .eq("id", fix_run_id)
            .limit(1)
            .execute()
            .data
            or []
        )
        row_data = row[0] if row else {}
        status_raw = row_data.get("status", "unknown")
        vresults = row_data.get("validation_results") or []
        sresults = row_data.get("step_results") or []
        rescans = [v for v in vresults if v.get("is_rescan")]
        passed_rescans = [v for v in rescans if v.get("passed")]

        # Count structured EDIT_FILE steps that actually landed (exit_code=0
        # and the command was a structured edit — identified by the EDIT_PATH=
        # env-var prefix our base64 executor uses).
        successful_edits = sum(
            1
            for s in sresults
            if s.get("status") == "success" and "EDIT_PATH=" in (s.get("command") or "")
        )
        # Total structured edits attempted (regardless of outcome)
        attempted_edits = sum(1 for s in sresults if "EDIT_PATH=" in (s.get("command") or ""))

        # Reclassify status. Priority order matters:
        #   1) partial_success — mixed re-scan outcomes (some fixed some not)
        #   2) no_fix_needed — 0 edits actually applied AND validation passes
        #      (KB adapter picked wrong literals OR file was already clean)
        #   3) success / rolled_back / failed — unchanged
        if status_raw == "success" and len(rescans) > 1 and 0 < len(passed_rescans) < len(rescans):
            status = "partial_success"
        elif status_raw == "success" and attempted_edits > 0 and successful_edits == 0:
            status = "no_fix_needed"
        else:
            status = status_raw

        findings_covered += pkg_findings
        fix_runs.append({"package_id": pkg["id"], "fix_run_id": fix_run_id, "status": status})

        # Honest per-check coverage: determine how many DISTINCT check_ids
        # the passing re-scans verify. This caps the fixed count so a single
        # narrow re-scan (e.g. --check CKV_AWS_21) cannot be scaled up to
        # credit all N findings in a batch. If ANY passing re-scan is broad
        # (whole-file scan asserting zero total failures), all pkg_findings
        # can honestly be credited.
        distinct_passing_check_ids: set[str] = set()
        any_broad_passing_rescan = False
        for _rs in passed_rescans:
            _ids, _broad = _rescan_covers_check_ids(
                _rs.get("command", "") or "",
                _rs.get("expected", "") or "",
            )
            distinct_passing_check_ids |= _ids
            if _broad:
                any_broad_passing_rescan = True

        if any_broad_passing_rescan:
            _fixed_ceiling = pkg_findings
        elif distinct_passing_check_ids:
            _fixed_ceiling = min(pkg_findings, len(distinct_passing_check_ids))
        else:
            # Passing re-scans present but no check_id extracted from any of
            # them (weird shape). Conservative: credit exactly 1 finding per
            # passing re-scan, capped at pkg_findings.
            _fixed_ceiling = min(pkg_findings, len(passed_rescans))

        if status == "success":
            succeeded += 1
            # Only credit up to _fixed_ceiling — the rest go to unaddressed
            # (never rescanned, so we can't claim they're fixed).
            _fixed_here = _fixed_ceiling
            _unaddressed_here = pkg_findings - _fixed_here
            findings_fixed += _fixed_here
            findings_unaddressed += _unaddressed_here
        elif status == "partial_success":
            partial += 1
            # Some rescans passed, some failed. Fixed = honest ceiling above.
            # Remain = the pkg_findings minus fixed (they were attempted and
            # something didn't stick — either failing rescan or unaddressed).
            _fixed_here = _fixed_ceiling
            findings_fixed += _fixed_here
            findings_remain += pkg_findings - _fixed_here
        elif status == "no_fix_needed":
            # Nothing was actually edited but the file is clean. Report
            # honestly as its own bucket — NOT fixed (we did nothing),
            # NOT rolled back (nothing broke). Findings stay uncovered.
            no_fix_needed_count += 1
            findings_no_fix_needed += pkg_findings
        elif status == "rolled_back":
            rolled_back += 1
            findings_remain += pkg_findings
        else:
            failed += 1
            findings_remain += pkg_findings

    result = {
        "skipped": False,
        "total": len(pkg_rows),
        "succeeded": succeeded,
        "partial": partial,
        "no_fix_needed": no_fix_needed_count,
        "failed": failed,
        "rolled_back": rolled_back,
        "findings_covered": findings_covered,
        "findings_fixed": findings_fixed,
        "findings_remain": findings_remain,
        "findings_no_fix_needed": findings_no_fix_needed,
        "findings_unaddressed": findings_unaddressed,
        "fix_runs": fix_runs,
    }
    # Trace summary — omit optional buckets when zero to keep it tight
    _nfn_suffix = f", {findings_no_fix_needed} no-fix-needed" if findings_no_fix_needed else ""
    _un_suffix = f", {findings_unaddressed} unaddressed" if findings_unaddressed else ""
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received FIX_DONE — {findings_fixed} fixed, {findings_remain} rolled back"
        f"{_nfn_suffix}{_un_suffix} (across {len(pkg_rows)} file package(s))",
    )
    return {"fix_result": result}


def _summarize_node(state: DemoMasterState) -> dict:
    """Finalize the demo run — update agent_runs, emit DONE."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    sample = state.get("sample_result", {})
    remediation = state.get("remediation_result", {})
    fix = state.get("fix_result", {})

    sampled = sample.get("sampled", 0)

    sb.table("agent_runs").update(
        {
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
        }
    ).eq("run_id", run_id).execute()

    if fix.get("skipped"):
        fix_summary = "fix stage skipped"
    else:
        # Finding-level report — user-facing counts.
        f_fixed = fix.get("findings_fixed", 0)
        f_remain = fix.get("findings_remain", 0)
        f_nfn = fix.get("findings_no_fix_needed", 0)
        f_un = fix.get("findings_unaddressed", 0)
        fix_summary = f"{f_fixed} fixed · {f_remain} rolled back"
        if f_nfn:
            fix_summary += f" · {f_nfn} no-fix-needed"
        if f_un:
            fix_summary += f" · {f_un} unaddressed"

    emit_trace_demo(
        run_id,
        "master",
        "DONE",
        f"DEMO_COMPLETE — {sampled} sampled · "
        f"{remediation.get('persisted', 0)} remediation package(s) generated · {fix_summary}",
        payload={
            "from": "master",
            "status": "DEMO_COMPLETE",
            "scan_id": run_id,
            "records_sampled": sampled,
            "families_found": sample.get("families_found", []),
            "families_missing": sample.get("families_missing", []),
            "records_enriched": sampled,  # Already enriched from real pipeline
            "records_remediated": remediation.get("persisted", 0),
            "epss_hits": 0,
            "kev_hits": 0,
            "nvd_hits": 0,
            "fix_result": fix,
        },
    )
    return {}


def _fail_node(state: DemoMasterState) -> dict:
    """Mark demo run as failed. Stashes the error under summary.error since
    agent_runs has no dedicated error column (migration 0001 shape)."""
    run_id = state["run_id"]
    msg = state.get("error_message") or "Unknown error"
    sb = supabase_admin_demo()
    sb.table("agent_runs").update(
        {
            "status": "failed",
            "completed_at": datetime.now(UTC).isoformat(),
            "summary": {"error": msg[:1000], "from": "master_demo"},
        }
    ).eq("run_id", run_id).execute()
    emit_trace_demo(run_id, "master", "ERROR", f"Demo run failed: {msg[:300]}")
    return {}


# ============================================================================
# Graph
# ============================================================================


def _build_graph():
    graph = StateGraph(DemoMasterState)
    graph.add_node("load_context", _load_context_node)
    graph.add_node("sample", _sample_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("remediate", _remediate_node)
    graph.add_node("fix", _fix_node)
    graph.add_node("summarize", _summarize_node)
    graph.add_node("fail", _fail_node)

    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "sample")
    graph.add_edge("sample", "remediate")
    graph.add_edge("remediate", "fix")
    graph.add_edge("fix", "summarize")
    graph.add_edge("summarize", END)
    graph.add_edge("fail", END)

    return graph.compile()


_GRAPH = _build_graph()


def run_demo_master(run_id: str, real_run_id: str | None = None) -> None:
    """Compile-once graph, invoke per run. Falls back to _fail_node on exception.

    Args:
        run_id: the demo agent_run_id.
        real_run_id: optional — the linked real fetch's run_id whose -ec2 output
            we should sample from. When called from /agents/trigger_demo this
            is always set (chained flow); when called standalone it's None
            (samples across all -ec2 issues).
    """
    try:
        _GRAPH.invoke({"run_id": run_id, "real_run_id": real_run_id})
    except RunCancelledError:
        # Cancellation was already recorded by the sub-agent that detected it —
        # don't call _fail_node (which would overwrite the cancelled status).
        pass
    except Exception as e:  # noqa: BLE001
        _fail_node({"run_id": run_id, "error_message": f"{type(e).__name__}: {str(e)[:300]}"})
