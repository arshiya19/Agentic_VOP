"""Day-3 CLI: run Sub-Agent 3 against the 5 demo issues and print the packages.

Usage (from apps/api/):
  uv run python scripts/run_planner.py
  uv run python scripts/run_planner.py 8585           # one specific issue
  uv run python scripts/run_planner.py --json         # full JSON, not pretty summary

No persistence of packages yet — that's Day 5. This is a sanity-check that
Sub-Agent 3 produces investor-grade output for the 5 demo IDs.

The script creates ONE agent_runs row per invocation so that LLM trace
events (cost, token usage) land cleanly without violating the
agent_trace_events.run_id foreign key constraint.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Make the app package importable when running from apps/api/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.remediation.planner import persist_package, plan_remediation
from app.db import supabase_admin


DEMO_ISSUE_IDS = [8585, 8586, 7481, 6394, 7832]


def _create_run(sb) -> str:
    """Insert a synthetic agent_runs row so LLM trace events have a valid FK.
    Returns the run_id.
    """
    run_id = str(uuid.uuid4())
    event_id = f"remediation-planner-cli-{int(time.time() * 1000)}"
    sb.table("agent_runs").insert({
        "run_id": run_id,
        "event_id": event_id,
        "triggered_by": "remediation_planner_cli",
        "action": "FULL",
        "targets": {"scanners": [], "scope": ["remediation_planner_demo"]},
        "status": "running",
    }).execute()
    return run_id


def _complete_run(sb, run_id: str, *, ok: bool, count: int) -> None:
    sb.table("agent_runs").update({
        "status": "completed" if ok else "failed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"agent": "sub-agent-3", "packages_generated": count},
    }).eq("run_id", run_id).execute()


def _load_issue(sb, issue_id: int) -> dict:
    resp = (
        sb.table("issues")
        .select(
            "id,source,severity,priority,cve_id,cwe_id,title,description,"
            "asset_identity,package,runtime_hostname,runtime_ipv4,"
            "runtime_os_family,runtime_purl"
        )
        .eq("id", issue_id)
        .limit(1)
        .execute()
    )
    if not resp.data:
        raise SystemExit(f"Issue id={issue_id} not found")
    return resp.data[0]


def _print_summary(pkg) -> None:
    print(f"\n{'=' * 72}")
    print(f"  Issue {pkg.issue_id} — Family: {pkg.family} — "
          f"Approval: {pkg.approval_required}")
    print(f"{'=' * 72}")
    print(f"\nFINDING\n  {pkg.finding}")
    print(f"\nROOT CAUSE\n  {pkg.root_cause}")
    print(f"\nIMPACT\n  {pkg.impact}")

    rec = pkg.recommended_pathway_index
    print(f"\nPATHWAYS ({len(pkg.pathways)} — recommended: #{rec + 1})")

    for idx, pw in enumerate(pkg.pathways):
        marker = "  ★ RECOMMENDED" if idx == rec else ""
        print(f"\n  ── Pathway {idx + 1} of {len(pkg.pathways)} ──{marker}")
        print(f"  Objective: {pw.objective}")
        print(f"  Security Coverage: {pw.security_coverage}")

        print(f"\n  REMEDIATION ({len(pw.remediation_steps)} steps):")
        for i, s in enumerate(pw.remediation_steps, 1):
            print(f"    {i}. {s.step}")
            print(f"       [Source: {s.source}]")

        rb = pw.rollback_plan
        print(f"\n  ROLLBACK PLAN (supported={rb.supported}):")
        print(f"    Objective: {rb.objective}")
        if rb.preconditions:
            print(f"    Preconditions:")
            for p in rb.preconditions:
                print(f"      • {p}")
        if rb.steps:
            print(f"    Steps ({len(rb.steps)}):")
            for i, s in enumerate(rb.steps, 1):
                print(f"      {i}. {s.step}")
                print(f"         [Source: {s.source}]")
        if rb.limitations:
            print(f"    Limitations:")
            for lim in rb.limitations:
                print(f"      • {lim}")
        print(f"    Explanation: {rb.explanation}")
        if not rb.supported and rb.recommended_recovery:
            print(f"    Recommended Recovery: {rb.recommended_recovery}")

        print(f"\n  VALIDATION TESTS ({len(pw.validation_tests)}):")
        for t in pw.validation_tests:
            print(f"    • {t.name}")
            print(f"        command:  {t.command[:110]}")
            print(f"        expected: {t.expected[:110]}")

        if pw.test_scripts:
            print(f"\n  TEST SCRIPTS ({len(pw.test_scripts)}):")
            for ts in pw.test_scripts:
                print(f"    • {ts.language} — {ts.description}")

        print(f"\n  EXECUTION STRATEGY")
        print(f"    {pw.execution_strategy}")

        if pw.advantages:
            print(f"\n  ADVANTAGES:")
            for a in pw.advantages:
                print(f"    + {a}")
        if pw.considerations:
            print(f"  CONSIDERATIONS:")
            for c in pw.considerations:
                print(f"    - {c}")

        if pw.validation_metadata:
            vm = pw.validation_metadata
            print(f"\n  VALIDATION METADATA")
            print(f"    Status: {vm.status}   Confidence: {vm.confidence}   When: {vm.timestamp[:19]}")
            print(f"    Sources: {', '.join(vm.sources)}")

        if pw.confidence_score is not None:
            print(f"\n  CONFIDENCE SCORE: {pw.confidence_score}/100")
            if pw.confidence_components:
                for name, comp in pw.confidence_components.items():
                    bar = "█" * comp["score"] + "·" * (comp["max_score"] - comp["score"])
                    print(f"     {name:<28} {comp['score']:>3}/{comp['max_score']:<3} [{bar}]")
                    print(f"       └─ {comp['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue_ids", nargs="*", type=int, default=DEMO_ISSUE_IDS)
    parser.add_argument("--json", action="store_true", help="emit full JSON instead of summary")
    parser.add_argument("--persist", action="store_true",
                        help="persist each generated package to remediation_packages table")
    args = parser.parse_args()

    sb = supabase_admin()
    run_id = _create_run(sb)
    print(f"agent_runs row created: {run_id}\n")
    successes = 0
    try:
        for issue_id in args.issue_ids:
            issue = _load_issue(sb, issue_id)
            t0 = time.perf_counter()
            try:
                pkg = plan_remediation(issue, run_id=run_id, sb=sb)
            except Exception as exc:
                print(f"\nFAILED for issue {issue_id}: {type(exc).__name__}: {exc}")
                continue
            successes += 1
            elapsed = time.perf_counter() - t0
            if args.json:
                print(json.dumps(pkg.model_dump(), indent=2, default=str))
            else:
                _print_summary(pkg)
                print(f"\n  ⏱  generated in {elapsed:.1f}s")
            if args.persist:
                pkg_id = persist_package(pkg, run_id=run_id, sb=sb)
                print(f"  💾 persisted as remediation_packages.id={pkg_id}")
    finally:
        _complete_run(sb, run_id, ok=(successes == len(args.issue_ids)), count=successes)
        print(f"\nagent_runs row {run_id} marked completed ({successes}/{len(args.issue_ids)} packages).")


if __name__ == "__main__":
    main()
