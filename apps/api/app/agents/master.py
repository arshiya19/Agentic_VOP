"""Master Agent — Supervisor / Orchestrator.

Real version will: use LangGraph + Claude Opus to plan, dispatch, retry, and
aggregate. For v1 the orchestration is a deterministic fan-out across each
scanner in the trigger's `targets.scanners` list.

ENRICH (Sub-Agent 2) is intentionally NOT wired yet.

Triggered as a FastAPI BackgroundTask from POST /agents/trigger.

Trigger payload conventions:
    targets.scanners: ["tenable"]                          → just Tenable
    targets.scanners: ["tenable", "trivy_results", ...]    → fan out
    targets.scanners: ["all"]                              → fan out across every enabled scanner
"""

from datetime import datetime, timezone

from ..db import supabase_admin
from . import sub_agent_1, sub_agent_2
from .trace import emit_trace


def run_master(run_id: str) -> None:
    """Pick up a queued run, dispatch to Sub-Agent 1 for each scanner, mark FETCH phase complete."""
    sb = supabase_admin()

    try:
        # 1. Mark running
        sb.table("agent_runs").update({"status": "running"}).eq("run_id", run_id).execute()
        emit_trace(run_id, "master", "DISPATCH", "Run started, planning")

        # 2. Resolve targets
        run = (
            sb.table("agent_runs")
            .select("*")
            .eq("run_id", run_id)
            .single()
            .execute()
            .data
        )
        scanners = run["targets"].get("scanners", [])
        if not scanners:
            raise ValueError("no scanners specified in targets")

        # Special: ["all"] expands to every enabled tool in connection_registry
        if scanners == ["all"]:
            registry_rows = (
                sb.table("connection_registry")
                .select("tool")
                .eq("enabled", True)
                .execute()
                .data
                or []
            )
            scanners = [r["tool"] for r in registry_rows]
            emit_trace(
                run_id, "master", "MESSAGE",
                f"Expanded 'all' → {len(scanners)} scanner(s): {', '.join(scanners)}",
            )

        correlation_id = f"corr-{run_id[:8]}"
        per_scanner: dict[str, dict] = {}
        total_inserted = 0

        # 3. Fan out: one FETCH dispatch per scanner
        for tool in scanners:
            registry_result = (
                sb.table("connection_registry")
                .select("*")
                .eq("tool", tool)
                .limit(1)
                .execute()
            )
            registry_row = (
                registry_result.data[0]
                if registry_result and registry_result.data
                else None
            )

            if not registry_row:
                emit_trace(
                    run_id, "master", "ERROR",
                    f"No connector registered for tool '{tool}' — skipping. "
                    f"(Have you applied migration 0006?)",
                )
                per_scanner[tool] = {"error": "no connector", "inserted": 0}
                continue

            emit_trace(
                run_id, "master", "DISPATCH",
                f"Sent FETCH command to sub-agent-1 (tool: {tool})",
                payload={
                    "action": "FETCH",
                    "scan_id": run_id,
                    "sub_agent_id": "sub-agent-1",
                    "tool": tool,
                    "protocol": registry_row["protocol"],
                    "correlation_id": correlation_id,
                },
            )

            try:
                inserted = sub_agent_1.run_fetch(run_id, tool, registry_row)
                per_scanner[tool] = {"inserted": inserted}
                total_inserted += inserted
            except Exception as e:
                emit_trace(
                    run_id, "master", "ERROR",
                    f"Sub-Agent 1 failed for tool '{tool}': {type(e).__name__}: {str(e)[:300]}",
                )
                per_scanner[tool] = {"error": str(e)[:200], "inserted": 0}
                # Continue to next scanner — partial success is better than aborting
                continue

            emit_trace(
                run_id, "master", "MESSAGE",
                f"Received FETCH_DONE for {tool} — {per_scanner[tool]['inserted']} canonical Issues",
                payload={
                    "received_from": "sub-agent-1",
                    "tool": tool,
                    "records_inserted": per_scanner[tool]["inserted"],
                    "correlation_id": correlation_id,
                },
            )

        emit_trace(
            run_id, "master", "MESSAGE",
            f"FETCH phase complete — {total_inserted} canonical Issues across {len(scanners)} scanner(s).",
            payload={
                "phase_complete": "FETCH",
                "total_findings": total_inserted,
                "per_scanner": per_scanner,
                "correlation_id": correlation_id,
            },
        )

        # 4. Dispatch ENRICH to Sub-Agent 2
        emit_trace(
            run_id, "master", "DISPATCH",
            "Sent ENRICH command to sub-agent-2",
            payload={
                "action": "ENRICH",
                "scan_id": run_id,
                "sub_agent_id": "sub-agent-2",
                "correlation_id": correlation_id,
            },
        )

        try:
            enrich_result = sub_agent_2.run_enrich(run_id)
        except Exception as e:
            emit_trace(
                run_id, "master", "ERROR",
                f"Sub-Agent 2 failed: {type(e).__name__}: {str(e)[:300]}",
            )
            enrich_result = {"enriched": 0, "failed": 0, "error": str(e)[:200]}

        emit_trace(
            run_id, "master", "MESSAGE",
            f"Received ENRICH_DONE — {enrich_result.get('enriched', 0)} issues enriched "
            f"(EPSS: {enrich_result.get('epss_hits', 0)}, KEV: {enrich_result.get('kev_hits', 0)}, "
            f"NVD: {enrich_result.get('nvd_hits', 0)})",
            payload={
                "received_from": "sub-agent-2",
                "enrich_result": enrich_result,
                "correlation_id": correlation_id,
            },
        )

        # 5. Mark run completed with full summary
        sb.table("agent_runs").update(
            {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "phase": "FETCH+ENRICH",
                    "total_findings": total_inserted,
                    "tools_processed": scanners,
                    "per_scanner": per_scanner,
                    "enriched": enrich_result.get("enriched", 0),
                    "epss_hits": enrich_result.get("epss_hits", 0),
                    "kev_hits": enrich_result.get("kev_hits", 0),
                    "nvd_hits": enrich_result.get("nvd_hits", 0),
                },
            }
        ).eq("run_id", run_id).execute()

        emit_trace(
            run_id, "master", "MESSAGE",
            f"SCAN_COMPLETE — {total_inserted} findings, {enrich_result.get('enriched', 0)} enriched.",
            payload={
                "event_type": "SCAN_COMPLETE",
                "scan_id": run_id,
                "summary": {
                    "total_findings": total_inserted,
                    "enriched": enrich_result.get("enriched", 0),
                },
                "correlation_id": correlation_id,
            },
        )

    except Exception as e:
        emit_trace(run_id, "master", "ERROR", f"Run failed: {e}")
        sb.table("agent_runs").update(
            {
                "status": "failed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        ).eq("run_id", run_id).execute()
