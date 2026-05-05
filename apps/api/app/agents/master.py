"""Master Agent — Supervisor / Orchestrator (LLM-driven).

Per the doc spec, Master uses an LLM (`master` prompt in prompt_db) to produce
a structured `MasterPlan`: an ordered list of FETCH and ENRICH steps. Code
then executes the plan step by step, dispatching to Sub-Agent 1 / Sub-Agent 2.

Why LLM here:
  - Decides which scanners to fetch based on the trigger payload.
  - Filters out scanners not registered in `connection_registry`.
  - Orders steps by priority and writes a 1-line reasoning per step (visible
    in the Agents page trace).
  - Future: dynamic conditional routing (e.g., skip ENRICH if 0 findings,
    fan out by tool family, retry on failure).

Triggered as a FastAPI BackgroundTask from POST /agents/trigger.

Trigger payload conventions:
    targets.scanners: ["osv"]                  → just OSV
    targets.scanners: ["osv", "tenable", ...]  → fan out
    targets.scanners: ["all"]                  → fan out across every enabled scanner
"""

import json
import re
from datetime import datetime

from ..db import supabase_admin
from ..models import MasterPlan
from . import sub_agent_1, sub_agent_2
from .llm import get_client
from .trace import emit_trace


_MASTER_PLAN_SCHEMA = MasterPlan.model_json_schema()
_BAD_UNICODE_ESCAPE = re.compile(r"\\u(?![0-9a-fA-F]{4})")
_ANY_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{0,4}")


def _parse_function_args(args_str: str) -> dict:
    """json.loads with multi-stage repair for malformed \\u escapes."""
    try:
        return json.loads(args_str)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_BAD_UNICODE_ESCAPE.sub(r"\\u0020", args_str))
    except json.JSONDecodeError:
        pass
    return json.loads(_ANY_UNICODE_ESCAPE.sub("", args_str))


def run_master(run_id: str) -> None:
    """Plan via LLM, then execute each step. Mark run completed."""
    sb = supabase_admin()

    try:
        # 1. Mark running
        sb.table("agent_runs").update({"status": "running"}).eq("run_id", run_id).execute()
        emit_trace(run_id, "master", "DISPATCH", "Run started, planning")

        # 2. Load run + Master prompt + available connectors
        run = sb.table("agent_runs").select("*").eq("run_id", run_id).single().execute().data

        prompt_row = (
            sb.table("prompt_db")
            .select("*")
            .eq("agent", "master")
            .eq("is_active", True)
            .single()
            .execute()
            .data
        )

        registry_rows = (
            sb.table("connection_registry")
            .select("tool, protocol, metadata")
            .eq("enabled", True)
            .execute()
            .data
            or []
        )
        available_tools = [
            {
                "tool": r["tool"],
                "protocol": r["protocol"],
                "connector_type": (r.get("metadata") or {}).get("connector_type"),
            }
            for r in registry_rows
        ]

        # 3. LLM call to produce the plan
        plan = _llm_plan(prompt_row, run, available_tools)

        emit_trace(
            run_id,
            "master",
            "MESSAGE",
            f"Plan ({len(plan.steps)} step(s)): {plan.plan_summary}",
            payload={"plan": plan.model_dump()},
        )

        # 4. Execute the plan step by step
        correlation_id = f"corr-{run_id[:8]}"
        per_scanner: dict[str, dict] = {}
        total_inserted = 0
        enrich_result: dict = {}

        for i, step in enumerate(plan.steps):
            step_label = f"Step {i + 1}/{len(plan.steps)}"

            if step.kind == "FETCH":
                tool = step.tool
                if not tool:
                    emit_trace(
                        run_id,
                        "master",
                        "ERROR",
                        f"{step_label}: FETCH step missing 'tool', skipping",
                    )
                    continue

                registry_result = (
                    sb.table("connection_registry").select("*").eq("tool", tool).limit(1).execute()
                )
                registry_row = (
                    registry_result.data[0] if registry_result and registry_result.data else None
                )
                if not registry_row:
                    emit_trace(
                        run_id,
                        "master",
                        "ERROR",
                        f"{step_label}: no connector for tool '{tool}', skipping",
                    )
                    per_scanner[tool] = {"error": "no connector", "inserted": 0}
                    continue

                emit_trace(
                    run_id,
                    "master",
                    "DISPATCH",
                    f"{step_label}: FETCH from {tool} — {step.notes or ''}",
                    payload={
                        "action": "FETCH",
                        "scan_id": run_id,
                        "sub_agent_id": "sub-agent-1",
                        "tool": tool,
                        "protocol": registry_row["protocol"],
                        "correlation_id": correlation_id,
                        "step_notes": step.notes,
                    },
                )

                try:
                    inserted = sub_agent_1.run_fetch(run_id, tool, registry_row)
                    per_scanner[tool] = {"inserted": inserted}
                    total_inserted += inserted
                except Exception as e:
                    emit_trace(
                        run_id,
                        "master",
                        "ERROR",
                        f"Sub-Agent 1 failed for tool '{tool}': {type(e).__name__}: {str(e)[:300]}",
                    )
                    per_scanner[tool] = {"error": str(e)[:200], "inserted": 0}
                    continue

                emit_trace(
                    run_id,
                    "master",
                    "MESSAGE",
                    f"Received FETCH_DONE for {tool} — "
                    f"{per_scanner[tool]['inserted']} canonical Issues",
                    payload={
                        "received_from": "sub-agent-1",
                        "tool": tool,
                        "records_inserted": per_scanner[tool]["inserted"],
                        "correlation_id": correlation_id,
                    },
                )

            elif step.kind == "ENRICH":
                emit_trace(
                    run_id,
                    "master",
                    "DISPATCH",
                    f"{step_label}: ENRICH — {step.notes or ''}",
                    payload={
                        "action": "ENRICH",
                        "scan_id": run_id,
                        "sub_agent_id": "sub-agent-2",
                        "correlation_id": correlation_id,
                        "step_notes": step.notes,
                    },
                )

                try:
                    enrich_result = sub_agent_2.run_enrich(run_id)
                except Exception as e:
                    emit_trace(
                        run_id,
                        "master",
                        "ERROR",
                        f"Sub-Agent 2 failed: {type(e).__name__}: {str(e)[:300]}",
                    )
                    enrich_result = {"enriched": 0, "error": str(e)[:200]}

                emit_trace(
                    run_id,
                    "master",
                    "MESSAGE",
                    f"Received ENRICH_DONE — {enrich_result.get('enriched', 0)} issues enriched "
                    f"(EPSS: {enrich_result.get('epss_hits', 0)}, "
                    f"KEV: {enrich_result.get('kev_hits', 0)}, "
                    f"NVD: {enrich_result.get('nvd_hits', 0)})",
                    payload={
                        "received_from": "sub-agent-2",
                        "enrich_result": enrich_result,
                        "correlation_id": correlation_id,
                    },
                )

        # 5. Mark run completed
        sb.table("agent_runs").update(
            {
                "status": "completed",
                "completed_at": datetime.now(datetime.UTC).isoformat(),
                "summary": {
                    "plan": plan.model_dump(),
                    "total_findings": total_inserted,
                    "per_scanner": per_scanner,
                    "enriched": enrich_result.get("enriched", 0),
                    "epss_hits": enrich_result.get("epss_hits", 0),
                    "kev_hits": enrich_result.get("kev_hits", 0),
                    "nvd_hits": enrich_result.get("nvd_hits", 0),
                },
            }
        ).eq("run_id", run_id).execute()

        emit_trace(
            run_id,
            "master",
            "MESSAGE",
            f"SCAN_COMPLETE — {total_inserted} findings, "
            f"{enrich_result.get('enriched', 0)} enriched.",
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
        emit_trace(
            run_id,
            "master",
            "ERROR",
            f"Run failed: {type(e).__name__}: {str(e)[:300]}",
        )
        sb.table("agent_runs").update(
            {
                "status": "failed",
                "completed_at": datetime.now(datetime.UTC).isoformat(),
            }
        ).eq("run_id", run_id).execute()


def _llm_plan(prompt_row: dict, run: dict, available_tools: list[dict]) -> MasterPlan:
    """Call OpenAI with function calling to produce a structured MasterPlan."""
    client = get_client()

    user_payload = {
        "trigger": {
            "event_id": run.get("event_id"),
            "action": run.get("action"),
            "persona": run.get("triggered_by"),
            "targets": run.get("targets") or {},
        },
        "available_tools": available_tools,
    }

    params = prompt_row.get("parameters") or {}

    response = client.chat.completions.create(
        model=prompt_row["model"],
        max_tokens=int(params.get("max_tokens", 1000)),
        temperature=float(params.get("temperature", 0.1)),
        messages=[
            {"role": "system", "content": prompt_row["prompt_text"]},
            {"role": "user", "content": json.dumps(user_payload, default=str)},
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "emit_master_plan",
                    "description": (
                        "Emit the orchestration plan: an ordered list of FETCH "
                        "and ENRICH steps for the sub-agents to execute."
                    ),
                    "parameters": _MASTER_PLAN_SCHEMA,
                },
            }
        ],
        tool_choice={"type": "function", "function": {"name": "emit_master_plan"}},
    )

    tool_calls = response.choices[0].message.tool_calls or []
    if not tool_calls:
        raise ValueError("Master LLM did not call emit_master_plan")

    parsed = _parse_function_args(tool_calls[0].function.arguments)
    return MasterPlan(**parsed)
