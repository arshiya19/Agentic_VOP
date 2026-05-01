"""Sub-Agent 2 — Enrichment Specialist (LLM-driven decisions).

For each canonical Issue produced in this run:
  1. EPSS    — exploit probability (FIRST.org public API, batched)
  2. CISA KEV — actively-exploited flag (catalog download)
  3. NVD     — CVSS v3 vector breakdown + CWE id (per-CVE; rate-limited
               unless NVD_API_KEY is set in env)
  4. **LLM call** — given the issue + all enrichment data, Claude decides
     derived_risk, risk_explanation, likelihood, impact, remediation_suggestion.
  5. Stamp enriched_at

Why LLM here: the same finding on a payments service vs a sandbox should
get different risk reasoning. A hardcoded formula can't articulate that.
The LLM does, and the explanation is stored alongside the score.

Deterministic pieces (HTTP calls, DB writes) stay code. Reasoning is LLM.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import httpx
from anthropic.types import ToolUseBlock

from ..config import settings
from ..db import supabase_admin
from ..models import LLMEnrichmentDecision
from .llm import get_client
from .trace import emit_trace


# Cached LLM tool input schema for the Sub-Agent 2 decision call
_DECISION_SCHEMA = LLMEnrichmentDecision.model_json_schema()


_EPSS_API = "https://api.first.org/data/v1/epss"
_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _llm_decide(
    prompt_row: dict,
    issue: dict,
    epss: dict,
    nvd: dict,
    in_kev: bool,
) -> LLMEnrichmentDecision:
    """Call Claude with tool_use to get the per-issue risk decision."""
    client = get_client()

    payload = {
        "issue": {
            "severity": issue.get("severity"),
            "cve_id": issue.get("cve_id"),
            "title": issue.get("title"),
            "description": issue.get("description"),
            "asset_identity": issue.get("asset_identity") or {},
            "package": issue.get("package"),
        },
        "enrichment": {
            "epss_score": epss.get("epss_score"),
            "epss_percentile": epss.get("epss_percentile"),
            "in_kev": in_kev,
            "nvd": nvd or {},
        },
    }

    params = prompt_row.get("parameters") or {}

    response = client.messages.create(
        model=prompt_row["model"],
        max_tokens=int(params.get("max_tokens", 800)),
        temperature=float(params.get("temperature", 0.2)),
        system=[
            {
                "type": "text",
                "text": prompt_row["prompt_text"],
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=[
            {
                "name": "emit_enrichment_decision",
                "description": (
                    "Emit the final risk decision for this issue: derived_risk, "
                    "risk_explanation, likelihood, impact, remediation_suggestion."
                ),
                "input_schema": _DECISION_SCHEMA,
            }
        ],
        tool_choice={"type": "tool", "name": "emit_enrichment_decision"},
        messages=[{"role": "user", "content": json.dumps(payload, default=str)}],
    )

    tool_block = next(
        (b for b in response.content if isinstance(b, ToolUseBlock)), None
    )
    if tool_block is None:
        raise ValueError("LLM did not call the emit_enrichment_decision tool")

    return LLMEnrichmentDecision(**tool_block.input)


def _fetch_nvd_data(cve_ids: list[str], api_key: str | None) -> dict[str, dict]:
    """For each CVE, fetch NVD data: CWE id + CVSS v3 vector breakdown.

    Throttle: 0.06s between calls with key (~50 req / 30s allowed),
              0.6s without (~5 req / 30s allowed).
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    delay = 0.06 if api_key else 0.6

    results: dict[str, dict] = {}
    with httpx.Client(timeout=30, headers=headers) as client:
        for cve in cve_ids:
            try:
                resp = client.get(_NVD_API, params={"cveId": cve})
                if resp.status_code != 200:
                    time.sleep(delay)
                    continue

                vulns = resp.json().get("vulnerabilities", []) or []
                if not vulns:
                    time.sleep(delay)
                    continue

                cve_data = vulns[0].get("cve", {}) or {}
                metrics = cve_data.get("metrics", {}) or {}

                # Prefer CVSS v3.1, fall back to v3.0
                cvss: dict | None = None
                for m in metrics.get("cvssMetricV31", []) or []:
                    if m.get("type") == "Primary":
                        cvss = m.get("cvssData") or {}
                        break
                if cvss is None:
                    for m in metrics.get("cvssMetricV30", []) or []:
                        if m.get("type") == "Primary":
                            cvss = m.get("cvssData") or {}
                            break

                # CWE id from weaknesses[]
                cwe_id: str | None = None
                for w in cve_data.get("weaknesses", []) or []:
                    for d in w.get("description", []) or []:
                        v = (d.get("value") or "").strip()
                        if v.upper().startswith("CWE-"):
                            cwe_id = v
                            break
                    if cwe_id:
                        break

                results[cve] = {
                    "cwe_id": cwe_id,
                    "cvss_attack_vector": (cvss or {}).get("attackVector"),
                    "cvss_attack_complexity": (cvss or {}).get("attackComplexity"),
                    "cvss_privileges_required": (cvss or {}).get("privilegesRequired"),
                    "cvss_user_interaction": (cvss or {}).get("userInteraction"),
                }
            except Exception:
                pass
            time.sleep(delay)

    return results


def run_enrich(run_id: str) -> dict:
    """Enrich canonical Issues from this run. Returns counts."""
    sb = supabase_admin()

    # Load Sub-Agent 2 prompt for the LLM decision step
    prompt_row = (
        sb.table("prompt_db")
        .select("*")
        .eq("agent", "sub-agent-2")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    # 1. Pull issues for this run
    issues = (
        sb.table("issues")
        .select("*")
        .eq("agent_run_id", run_id)
        .execute()
        .data
        or []
    )

    emit_trace(
        run_id, "sub-agent-2", "MESSAGE",
        f"Loaded {len(issues)} canonical Issues to enrich. "
        f"Using prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']})",
    )

    if not issues:
        emit_trace(
            run_id, "sub-agent-2", "DONE",
            "ENRICH_DONE — no issues to enrich",
            payload={
                "from": "sub-agent-2",
                "status": "ENRICH_DONE",
                "scan_id": run_id,
                "records_enriched": 0,
            },
        )
        return {"enriched": 0, "failed": 0}

    # 2. Collect unique CVE ids
    cve_ids: set[str] = set()
    for issue in issues:
        if issue.get("cve_id"):
            cve_ids.add(issue["cve_id"])
        for c in issue.get("all_cves") or []:
            cve_ids.add(c)

    emit_trace(
        run_id, "sub-agent-2", "MESSAGE",
        f"Collected {len(cve_ids)} unique CVE id(s) to look up",
    )

    # 3. EPSS lookup (batched — single request, up to 100 CVEs)
    epss_data: dict[str, dict] = {}
    if cve_ids:
        emit_trace(run_id, "sub-agent-2", "MESSAGE", "Querying EPSS (FIRST.org)…")
        try:
            with httpx.Client(timeout=30) as client:
                resp = client.get(
                    _EPSS_API,
                    params={"cve": ",".join(list(cve_ids)[:100])},
                )
                if resp.status_code == 200:
                    for entry in resp.json().get("data", []) or []:
                        cve = entry.get("cve")
                        if not cve:
                            continue
                        epss_data[cve] = {
                            "epss_score": float(entry["epss"]) if entry.get("epss") else None,
                            "epss_percentile": float(entry["percentile"]) if entry.get("percentile") else None,
                        }
            emit_trace(
                run_id, "sub-agent-2", "MESSAGE",
                f"EPSS returned data for {len(epss_data)} CVE(s)",
            )
        except Exception as e:
            emit_trace(
                run_id, "sub-agent-2", "ERROR",
                f"EPSS lookup failed: {type(e).__name__}: {str(e)[:200]}",
            )

    # 3b. NVD per-CVE lookup (CWE id + CVSS v3 vector breakdown)
    nvd_data: dict[str, dict] = {}
    if cve_ids:
        nvd_key = settings.nvd_api_key or None
        speed_note = (
            f"with API key (~{len(cve_ids) * 0.06:.0f}s expected)"
            if nvd_key
            else f"no API key — rate-limited (~{len(cve_ids) * 0.6:.0f}s expected)"
        )
        emit_trace(run_id, "sub-agent-2", "MESSAGE", f"Querying NVD ({speed_note})…")
        try:
            nvd_data = _fetch_nvd_data(list(cve_ids), nvd_key)
            emit_trace(
                run_id, "sub-agent-2", "MESSAGE",
                f"NVD returned data for {len(nvd_data)} CVE(s)",
            )
        except Exception as e:
            emit_trace(
                run_id, "sub-agent-2", "ERROR",
                f"NVD lookup failed: {type(e).__name__}: {str(e)[:200]}",
            )

    # 4. CISA KEV catalog (downloaded once per run)
    kev_set: set[str] = set()
    emit_trace(run_id, "sub-agent-2", "MESSAGE", "Downloading CISA KEV catalog…")
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(_KEV_CATALOG_URL)
            if resp.status_code == 200:
                for entry in resp.json().get("vulnerabilities", []) or []:
                    cve = entry.get("cveID")
                    if cve:
                        kev_set.add(cve)
        emit_trace(
            run_id, "sub-agent-2", "MESSAGE",
            f"CISA KEV catalog loaded ({len(kev_set)} actively-exploited CVEs)",
        )
    except Exception as e:
        emit_trace(
            run_id, "sub-agent-2", "ERROR",
            f"CISA KEV download failed: {type(e).__name__}: {str(e)[:200]}",
        )

    # 5. Update each issue
    enriched = 0
    failed = 0
    kev_hits = 0
    epss_hits = 0

    for i, issue in enumerate(issues):
        try:
            cve = issue.get("cve_id")

            # Assemble enrichment data fetched above
            epss = epss_data.get(cve, {}) if cve else {}
            epss_score = epss.get("epss_score")
            epss_percentile = epss.get("epss_percentile")
            if epss_score is not None:
                epss_hits += 1

            in_kev = (cve in kev_set) if cve else False
            if in_kev:
                kev_hits += 1

            nvd = nvd_data.get(cve, {}) if cve else {}

            # LLM decision: derived_risk, explanation, likelihood, impact, remediation
            decision = _llm_decide(prompt_row, issue, epss, nvd, in_kev)

            sb.table("issues").update(
                {
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "exploit_in_kev": in_kev,
                    "cwe_id": nvd.get("cwe_id"),
                    "cvss_attack_vector": nvd.get("cvss_attack_vector"),
                    "cvss_attack_complexity": nvd.get("cvss_attack_complexity"),
                    "cvss_privileges_required": nvd.get("cvss_privileges_required"),
                    "cvss_user_interaction": nvd.get("cvss_user_interaction"),
                    # LLM-decided fields:
                    "likelihood": decision.likelihood,
                    "impact": decision.impact,
                    "derived_risk": decision.derived_risk,
                    "risk_explanation": decision.risk_explanation,
                    "remediation_suggestion": decision.remediation_suggestion,
                    "enriched_at": datetime.now(timezone.utc).isoformat(),
                }
            ).eq("id", issue["id"]).execute()

            enriched += 1
        except Exception as e:
            failed += 1
            if failed <= 3:
                emit_trace(
                    run_id, "sub-agent-2", "ERROR",
                    f"Issue {issue.get('id')} enrichment failed "
                    f"({type(e).__name__}): {str(e)[:200]}",
                )

        if (i + 1) % 20 == 0 and (i + 1) < len(issues):
            emit_trace(
                run_id, "sub-agent-2", "MESSAGE",
                f"Enriched {i + 1}/{len(issues)} issues "
                f"({enriched} succeeded, {failed} failed so far)",
            )

    emit_trace(
        run_id, "sub-agent-2", "DONE",
        f"ENRICH_DONE — {enriched} issues enriched "
        f"(EPSS hits: {epss_hits}, KEV hits: {kev_hits}, NVD hits: {len(nvd_data)})",
        payload={
            "from": "sub-agent-2",
            "status": "ENRICH_DONE",
            "scan_id": run_id,
            "records_enriched": enriched,
            "records_failed": failed,
            "fields_added": [
                "epss_score",
                "epss_percentile",
                "exploit_in_kev",
                "cwe_id",
                "cvss_attack_vector",
                "cvss_attack_complexity",
                "cvss_privileges_required",
                "cvss_user_interaction",
                "likelihood",
                "impact",
                "derived_risk",
                "enriched_at",
            ],
            "epss_coverage": epss_hits,
            "kev_hits": kev_hits,
            "nvd_coverage": len(nvd_data),
        },
    )

    return {
        "enriched": enriched,
        "failed": failed,
        "kev_hits": kev_hits,
        "epss_hits": epss_hits,
        "nvd_hits": len(nvd_data),
    }
