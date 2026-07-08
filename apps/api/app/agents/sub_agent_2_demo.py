"""Sub-Agent 2 — DEMO orchestrator.

Enriches the 5 demo issues in demo.issues with EPSS score, KEV flag, NVD
data, priority scoring, and LLM-generated risk_explanation +
remediation_suggestion. Writes updates back to demo.issues.

Reuses pure helpers from `sub_agent_2.py`:
  _compute_score(issue, asset)       — deterministic priority formula
  _llm_decide(...)                    — LLM narrative (v1.4 prompt)
  _parse_nvd_response(vulns)         — NVD → dict projection
  _build_asset_index / _resolve_asset — asset attribution
  _sanitize                           — NUL byte stripper

Simplifications vs real sub_agent_2:
  - Skips DynamoDB Intelligence cache — always hits NVD API directly.
  - Skips MITRE (CAPEC/ATT&CK) lookups — the LLM decides without them.
  - Skips write-back to DynamoDB.

Config still shared with real pipeline (public.prompt_db for the
Sub-Agent 2 prompt). Traces go to demo.agent_trace_events via trace_demo.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

import httpx

from ..config import settings
from ..db import supabase_admin, supabase_admin_demo
from .http_utils import request_with_retry
from .sub_agent_2 import (
    _asset_for_llm,
    _build_asset_index,
    _compute_score,
    _fetch_nvd_data,
    _llm_decide,
    _parse_nvd_response,
    _resolve_asset,
    _sanitize,
)
from .trace_demo import RunCancelledError, emit_trace_demo, is_cancellation_requested_demo


_EPSS_API = "https://api.first.org/data/v1/epss"
_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def run_demo_enrich(run_id: str) -> dict:
    """Enrich demo issues written by sub_agent_1_demo.run_demo_fetch.

    Returns the same-shape dict as sub_agent_2.run_enrich so master_demo
    can log identical stats.
    """
    if is_cancellation_requested_demo(run_id):
        emit_trace_demo(
            run_id,
            "sub-agent-2",
            "MESSAGE",
            "Cancellation detected at enrichment entry — skipping",
        )
        raise RunCancelledError("Sub-Agent 2 (demo) stopped before enrichment")

    sb_demo = supabase_admin_demo()
    sb_pub = supabase_admin()  # for prompt_db (shared config)

    # ---- Load prompt (shared) ----
    prompt_row = (
        sb_pub.table("prompt_db")
        .select("*")
        .eq("agent", "sub-agent-2")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    # ---- 1. Load issues for this run + assets for scoring context ----
    issues = (
        sb_demo.table("issues").select("*").eq("agent_run_id", run_id).execute().data or []
    )
    emit_trace_demo(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Loaded {len(issues)} canonical Issue(s) from demo.issues to enrich. "
        f"Using prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']})",
    )

    asset_rows = sb_demo.table("assets").select("*").execute().data or []
    asset_index = _build_asset_index(asset_rows)
    emit_trace_demo(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Loaded {len(asset_rows)} asset rows from demo.assets for scoring context",
    )

    if not issues:
        emit_trace_demo(
            run_id,
            "sub-agent-2",
            "DONE",
            "ENRICH_DONE — no issues to enrich",
            payload={
                "from": "sub-agent-2",
                "status": "ENRICH_DONE",
                "scan_id": run_id,
                "records_enriched": 0,
            },
        )
        return {"enriched": 0, "failed": 0, "kev_hits": 0, "epss_hits": 0, "nvd_hits": 0}

    # ---- 2. Collect unique CVE ids across all issues ----
    cve_ids: set[str] = set()
    for issue in issues:
        if issue.get("cve_id"):
            cve_ids.add(issue["cve_id"])
        for c in issue.get("all_cves") or []:
            cve_ids.add(c)
    emit_trace_demo(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Collected {len(cve_ids)} unique CVE id(s) to look up",
    )

    # ---- 3. EPSS (single batched call) ----
    epss_data: dict[str, dict] = {}
    if cve_ids:
        emit_trace_demo(run_id, "sub-agent-2", "MESSAGE", "Querying EPSS (FIRST.org)…")
        try:
            with httpx.Client(timeout=30) as client:
                resp = request_with_retry(
                    client,
                    "GET",
                    _EPSS_API,
                    params={"cve": ",".join(list(cve_ids)[:100])},
                    timeout=30,
                    run_id=run_id,
                    agent="sub-agent-2",
                )
                for entry in resp.json().get("data", []) or []:
                    cve = entry.get("cve")
                    if not cve:
                        continue
                    epss_data[cve] = {
                        "epss_score": float(entry["epss"]) if entry.get("epss") else None,
                        "epss_percentile": float(entry["percentile"])
                        if entry.get("percentile")
                        else None,
                    }
            emit_trace_demo(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"EPSS returned data for {len(epss_data)} CVE(s)",
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "sub-agent-2",
                "ERROR",
                f"EPSS lookup failed: {type(e).__name__}: {str(e)[:200]}",
            )

    # ---- 4. NVD (per-CVE, direct — skip DynamoDB cache path) ----
    # Passes emit_fn=emit_trace_demo so nested emit_trace calls inside
    # _fetch_nvd_data / request_with_retry route into demo.agent_trace_events.
    nvd_data: dict[str, dict] = {}
    if cve_ids:
        emit_trace_demo(
            run_id,
            "sub-agent-2",
            "MESSAGE",
            f"Querying NVD API for {len(cve_ids)} CVE(s)…",
        )
        try:
            nvd_key = settings.nvd_api_key or None
            nvd_data = _fetch_nvd_data(
                list(cve_ids), nvd_key, run_id=run_id, emit_fn=emit_trace_demo
            )
            emit_trace_demo(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"NVD returned data for {len(nvd_data)} CVE(s)",
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "sub-agent-2",
                "ERROR",
                f"NVD lookup failed: {type(e).__name__}: {str(e)[:200]}",
            )

    # ---- 5. CISA KEV (simple: fetch catalog, intersect) ----
    kev_ids: set[str] = set()
    try:
        emit_trace_demo(run_id, "sub-agent-2", "MESSAGE", "Fetching CISA KEV catalog…")
        with httpx.Client(timeout=30) as client:
            resp = request_with_retry(
                client, "GET", _KEV_CATALOG_URL, timeout=30, run_id=run_id, agent="sub-agent-2"
            )
            for entry in resp.json().get("vulnerabilities", []) or []:
                if entry.get("cveID"):
                    kev_ids.add(entry["cveID"])
        emit_trace_demo(
            run_id,
            "sub-agent-2",
            "MESSAGE",
            f"KEV catalog: {len(kev_ids)} known-exploited CVE(s) total",
        )
    except Exception as e:  # noqa: BLE001
        emit_trace_demo(
            run_id,
            "sub-agent-2",
            "ERROR",
            f"KEV catalog fetch failed: {type(e).__name__}: {str(e)[:200]}",
        )

    # ---- 6. Per-issue enrichment (parallel workers) ----
    workers = max(1, int(settings.llm_parallel_workers or 10))
    emit_trace_demo(
        run_id, "sub-agent-2", "MESSAGE", f"Enriching {len(issues)} issue(s)…"
    )

    enriched = 0
    failed = 0
    epss_hits = 0
    kev_hits = 0

    def _process_one(issue: dict) -> dict:
        if is_cancellation_requested_demo(run_id):
            raise RunCancelledError(f"Skipping issue {issue.get('id')} — run cancelled")

        cve = issue.get("cve_id")
        epss = epss_data.get(cve, {}) if cve else {}
        epss_score = epss.get("epss_score")
        epss_pct = epss.get("epss_percentile")

        in_kev = bool(cve and cve in kev_ids)

        # NVD projection for this CVE
        nvd = _parse_nvd_response(nvd_data.get(cve, {}).get("vulns", [])) if cve else {}

        # Asset resolution + score
        asset = _resolve_asset(issue, asset_index)
        scoring = _compute_score(
            {
                **issue,
                "epss_score": epss_score,
                "epss_percentile": epss_pct,
                "exploit_in_kev": in_kev,
                "cve_id": cve,
                "cvss_score": issue.get("cvss_score") or nvd.get("cvss_score"),
                "cvss_attack_vector": nvd.get("cvss_attack_vector"),
            },
            asset,
        )

        # LLM narrative
        decision = _llm_decide(
            run_id=run_id,
            prompt_row=prompt_row,
            issue=issue,
            epss={"epss_score": epss_score, "epss_percentile": epss_pct},
            nvd=nvd,
            in_kev=in_kev,
            mitre=None,  # skipped in demo
            asset=asset,
            scoring=scoring,
            emit_fn=emit_trace_demo,
        )

        update_row = {
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "exploit_in_kev": in_kev,
            "cwe_id": (nvd.get("cwe_id") or issue.get("cwe_id")),
            "cvss_attack_vector": nvd.get("cvss_attack_vector"),
            "cvss_attack_complexity": nvd.get("cvss_attack_complexity"),
            "cvss_privileges_required": nvd.get("cvss_privileges_required"),
            "cvss_user_interaction": nvd.get("cvss_user_interaction"),
            "cvss_score": issue.get("cvss_score") or nvd.get("cvss_score"),
            "cvss_version": issue.get("cvss_version") or nvd.get("cvss_version"),
            # Asset-context denorm
            "exposure": (asset or {}).get("exposure"),
            "business_criticality": (asset or {}).get("business_criticality"),
            "asset_owner": (asset or {}).get("business_owner"),
            # Deterministic scoring
            "derived_risk": scoring["derived_risk"],
            "priority": scoring["priority"],
            "components_summary": scoring["components_summary"],
            "scoring_policy_version": scoring["scoring_policy_version"],
            # LLM prose — LLMEnrichmentDecision only has these two fields (v1.4+).
            "risk_explanation": decision.risk_explanation,
            "remediation_suggestion": decision.remediation_suggestion,
            "enriched_at": datetime.now(UTC).isoformat(),
        }
        sb_demo.table("issues").update(_sanitize(update_row)).eq("id", issue["id"]).execute()
        return {"epss_hit": epss_score is not None, "kev_hit": in_kev}

    cancelled = False
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_process_one, i): i for i in issues}
        for future in as_completed(futures):
            issue = futures[future]
            try:
                result = future.result()
                enriched += 1
                if result.get("epss_hit"):
                    epss_hits += 1
                if result.get("kev_hit"):
                    kev_hits += 1
            except RunCancelledError:
                cancelled = True
            except Exception as e:  # noqa: BLE001
                failed += 1
                if failed <= 3:
                    emit_trace_demo(
                        run_id,
                        "sub-agent-2",
                        "ERROR",
                        f"Issue {issue.get('id')} enrichment failed "
                        f"({type(e).__name__}): {str(e)[:200]}",
                    )

    if cancelled:
        emit_trace_demo(
            run_id,
            "sub-agent-2",
            "MESSAGE",
            f"Cancellation detected — stopped after enriching {enriched} issue(s)",
        )
        raise RunCancelledError("Sub-Agent 2 (demo) stopped due to user cancellation")

    emit_trace_demo(
        run_id,
        "sub-agent-2",
        "DONE",
        f"ENRICH_DONE — {enriched} issues enriched "
        f"(EPSS: {epss_hits}, KEV: {kev_hits}, NVD: {len(nvd_data)})",
        payload={
            "from": "sub-agent-2",
            "status": "ENRICH_DONE",
            "scan_id": run_id,
            "records_enriched": enriched,
            "records_failed": failed,
            "epss_coverage": epss_hits,
            "kev_hits": kev_hits,
            "nvd_coverage": len(nvd_data),
        },
    )

    # Token aggregation (mirrors real path)
    token_events = (
        sb_demo.table("agent_trace_events")
        .select("payload")
        .eq("run_id", run_id)
        .eq("agent", "sub-agent-2")
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

    return {
        "enriched": enriched,
        "failed": failed,
        "kev_hits": kev_hits,
        "epss_hits": epss_hits,
        "nvd_hits": len(nvd_data),
        "prompt_tokens": total_prompt,
        "completion_tokens": total_completion,
        "total_tokens": total_tokens_sum,
    }
