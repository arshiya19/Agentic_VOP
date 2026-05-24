"""Sub-Agent 2 — Enrichment Specialist (LangChain-powered decisions).

For each canonical Issue produced in this run:
  1. EPSS    — exploit probability (FIRST.org public API, batched)
  2. CISA KEV — actively-exploited flag (catalog download)
  3. NVD     — CVSS v3 vector breakdown + CWE id (per-CVE; rate-limited
               unless NVD_API_KEY is set in env)
  4. LLM call (ChatOpenAI.with_structured_output) — given the issue + all
     enrichment data, the LLM decides derived_risk, risk_explanation,
     likelihood, impact, remediation_suggestion.
  5. Stamp enriched_at

Why LLM here: the same finding on a payments service vs a sandbox should
get different risk reasoning. A hardcoded formula can't articulate that.
The LLM does, and the explanation is stored alongside the score.

Deterministic pieces (HTTP calls, DB writes) stay code. Reasoning is LLM.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

import httpx
from langchain_core.messages import HumanMessage, SystemMessage
from .http_utils import request_with_retry

from ..config import settings
from ..db import supabase_admin
from ..models import LLMEnrichmentDecision
from .llm import invoke_structured_with_retry
from .trace import emit_trace


_EPSS_API = "https://api.first.org/data/v1/epss"
_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _sanitize(value):
    """Recursively strip Postgres-incompatible NUL bytes from any string fields."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _llm_decide(
    run_id: str,
    prompt_row: dict,
    issue: dict,
    epss: dict,
    nvd: dict,
    in_kev: bool,
    mitre: dict | None = None,
) -> LLMEnrichmentDecision:
    """Call ChatOpenAI with structured output for the per-issue risk decision.

    Tiered retry — escalate temperature first, then escalate the model on the
    final attempt for issues the small model can't reason about.

    `mitre` is the full MITRE chain payload — shape:
        {"cwe": {...} | {}, "capec": [...], "attack": [...]}
    Sections may be empty when the local catalogs haven't been seeded or
    when the CVE has no CWE id.
    """
    params = prompt_row.get("parameters") or {}
    base_temp = float(params.get("temperature", 0.2))
    max_tokens = int(params.get("max_tokens", 800))
    primary_model = prompt_row["model"]
    fallback_model = params.get("fallback_model", "gpt-4o")

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
            "mitre": mitre or {"cwe": {}, "capec": [], "attack": []},
        },
    }

    return invoke_structured_with_retry(
        run_id=run_id,
        agent="sub-agent-2",
        schema=LLMEnrichmentDecision,
        messages=[
            SystemMessage(content=prompt_row["prompt_text"]),
            HumanMessage(content=str(payload)),
        ],
        attempts=[
            (base_temp, primary_model, max_tokens),
            (0.6, primary_model, max_tokens),
            (0.3, fallback_model, max_tokens),
        ],
    )


def _fetch_nvd_data(
    cve_ids: list[str], api_key: str | None, run_id: str | None = None
) -> dict[str, dict]:
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
                resp = request_with_retry(
                    client,
                    "GET",
                    _NVD_API,
                    params={"cveId": cve},
                    timeout=30,
                    run_id=run_id,
                    agent="sub-agent-2",
                )
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
            except Exception:  # nosec B110 — intentional: skip individual CVE NVD fetch failures, continue to next CVE  # noqa: S110
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
    issues = sb.table("issues").select("*").eq("agent_run_id", run_id).execute().data or []

    emit_trace(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Loaded {len(issues)} canonical Issues to enrich. "
        f"Using prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']})",
    )

    if not issues:
        emit_trace(
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
        return {"enriched": 0, "failed": 0}

    # 2. Collect unique CVE ids
    cve_ids: set[str] = set()
    for issue in issues:
        if issue.get("cve_id"):
            cve_ids.add(issue["cve_id"])
        for c in issue.get("all_cves") or []:
            cve_ids.add(c)

    emit_trace(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Collected {len(cve_ids)} unique CVE id(s) to look up",
    )

    # 3. EPSS lookup (batched — single request, up to 100 CVEs)
    epss_data: dict[str, dict] = {}
    if cve_ids:
        emit_trace(run_id, "sub-agent-2", "MESSAGE", "Querying EPSS (FIRST.org)…")
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
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"EPSS returned data for {len(epss_data)} CVE(s)",
            )
        except Exception as e:
            emit_trace(
                run_id,
                "sub-agent-2",
                "ERROR",
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
            nvd_data = _fetch_nvd_data(list(cve_ids), nvd_key, run_id=run_id)
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"NVD returned data for {len(nvd_data)} CVE(s)",
            )
        except Exception as e:
            emit_trace(
                run_id,
                "sub-agent-2",
                "ERROR",
                f"NVD lookup failed: {type(e).__name__}: {str(e)[:200]}",
            )

    # 3c. MITRE chain: CWE → CAPEC → ATT&CK
    # All three are local table joins (refreshed monthly by /admin/mitre/refresh*).
    # Each step is best-effort — empty tables just mean less context for the LLM.
    mitre_cwe_by_id: dict[str, dict] = {}
    mitre_capec_by_id: dict[str, dict] = {}
    mitre_attack_by_id: dict[str, dict] = {}

    # CWE ids come from TWO places — NVD (for CVE-having findings) and Sub-Agent 1
    # (for SAST-style findings that have a CWE but no CVE). We union them so MITRE
    # enrichment fires for both kinds of issues.
    cwe_ids_seen = {row.get("cwe_id") for row in nvd_data.values() if row.get("cwe_id")}
    for issue in issues:
        if issue.get("cwe_id"):
            cwe_ids_seen.add(issue["cwe_id"])
    if cwe_ids_seen:
        try:
            cwe_rows = (
                sb.table("mitre_cwe")
                .select(
                    "cwe_id,name,description,extended_description,"
                    "likelihood_of_exploit,consequences,mitigations,related_capec"
                )
                .in_("cwe_id", list(cwe_ids_seen))
                .execute()
                .data
                or []
            )
            mitre_cwe_by_id = {row["cwe_id"]: row for row in cwe_rows}
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"MITRE CWE matched {len(mitre_cwe_by_id)} of {len(cwe_ids_seen)} CWE id(s)",
            )
        except Exception as e:
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"MITRE CWE lookup skipped: {type(e).__name__}: {str(e)[:200]}",
            )

    # Collect CAPEC ids referenced by the CWEs we just loaded.
    capec_ids_seen: set[str] = set()
    for cwe_row in mitre_cwe_by_id.values():
        for capec_id in cwe_row.get("related_capec") or []:
            capec_ids_seen.add(capec_id)

    if capec_ids_seen:
        try:
            capec_rows = (
                sb.table("mitre_capec")
                .select(
                    "capec_id,name,description,likelihood_of_attack,typical_severity,"
                    "prerequisites,mitigations,related_attack_techniques"
                )
                .in_("capec_id", list(capec_ids_seen))
                .execute()
                .data
                or []
            )
            mitre_capec_by_id = {row["capec_id"]: row for row in capec_rows}
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"MITRE CAPEC matched {len(mitre_capec_by_id)} of "
                f"{len(capec_ids_seen)} attack pattern(s)",
            )
        except Exception as e:
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"MITRE CAPEC lookup skipped: {type(e).__name__}: {str(e)[:200]}",
            )

    # Collect ATT&CK technique ids referenced by the CAPECs we just loaded.
    attack_ids_seen: set[str] = set()
    for capec_row in mitre_capec_by_id.values():
        for tech_id in capec_row.get("related_attack_techniques") or []:
            attack_ids_seen.add(tech_id)

    if attack_ids_seen:
        try:
            attack_rows = (
                sb.table("mitre_attack_techniques")
                .select("technique_id,name,description,tactics,platforms")
                .in_("technique_id", list(attack_ids_seen))
                .execute()
                .data
                or []
            )
            mitre_attack_by_id = {row["technique_id"]: row for row in attack_rows}
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"MITRE ATT&CK matched {len(mitre_attack_by_id)} of "
                f"{len(attack_ids_seen)} technique id(s)",
            )
        except Exception as e:
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"MITRE ATT&CK lookup skipped: {type(e).__name__}: {str(e)[:200]}",
            )

    # 4. CISA KEV catalog (downloaded once per run)
    kev_set: set[str] = set()
    emit_trace(run_id, "sub-agent-2", "MESSAGE", "Downloading CISA KEV catalog…")
    try:
        with httpx.Client(timeout=30) as client:
            resp = request_with_retry(
                client, "GET", _KEV_CATALOG_URL, timeout=30, run_id=run_id, agent="sub-agent-2"
            )
            for entry in resp.json().get("vulnerabilities", []) or []:
                cve = entry.get("cveID")
                if cve:
                    kev_set.add(cve)
        emit_trace(
            run_id,
            "sub-agent-2",
            "MESSAGE",
            f"CISA KEV catalog loaded ({len(kev_set)} actively-exploited CVEs)",
        )
    except Exception as e:
        emit_trace(
            run_id,
            "sub-agent-2",
            "ERROR",
            f"CISA KEV download failed: {type(e).__name__}: {str(e)[:200]}",
        )

    # 5. Update each issue (parallel LLM decision)
    enriched = 0
    failed = 0
    kev_hits = 0
    epss_hits = 0

    workers = max(1, int(settings.llm_parallel_workers or 10))
    emit_trace(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Reasoning over {len(issues)} issue(s)…",
    )

    def _process_one(issue: dict) -> dict:
        """Per-issue task: assemble enrichment, call LLM, update row. Runs in a worker thread."""
        cve = issue.get("cve_id")
        epss = epss_data.get(cve, {}) if cve else {}
        epss_score = epss.get("epss_score")
        epss_percentile = epss.get("epss_percentile")
        in_kev = (cve in kev_set) if cve else False
        nvd = nvd_data.get(cve, {}) if cve else {}
        # Prefer the NVD-derived CWE (authoritative, comes from the official
        # CVE↔CWE mapping). Fall back to Sub-Agent 1's CWE when the finding
        # has no CVE (SAST findings, code-level weaknesses).
        cwe_id = nvd.get("cwe_id") or issue.get("cwe_id")

        # Assemble the chained MITRE payload for this issue:
        #   cwe   → the single CWE row matched by nvd.cwe_id
        #   capec → all CAPEC rows whose ids appear in cwe.related_capec
        #   attack→ all ATT&CK rows whose ids appear in any capec.related_attack_techniques
        cwe_row = mitre_cwe_by_id.get(cwe_id) if cwe_id else None
        capec_rows: list[dict] = []
        attack_rows: list[dict] = []
        if cwe_row:
            for capec_id in cwe_row.get("related_capec") or []:
                row = mitre_capec_by_id.get(capec_id)
                if row:
                    capec_rows.append(row)
            seen_techs: set[str] = set()
            for capec_row in capec_rows:
                for tech_id in capec_row.get("related_attack_techniques") or []:
                    if tech_id in seen_techs:
                        continue
                    row = mitre_attack_by_id.get(tech_id)
                    if row:
                        attack_rows.append(row)
                        seen_techs.add(tech_id)

        mitre_payload = {
            "cwe": cwe_row or {},
            "capec": capec_rows,
            "attack": attack_rows,
        }

        decision = _llm_decide(run_id, prompt_row, issue, epss, nvd, in_kev, mitre_payload)

        update_row = {
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "exploit_in_kev": in_kev,
            "cwe_id": cwe_id,
            # cwe_name: prefer MITRE (authoritative), fall back to NVD-supplied name if any.
            "cwe_name": (cwe_row or {}).get("name") or nvd.get("cwe_name"),
            "cvss_attack_vector": nvd.get("cvss_attack_vector"),
            "cvss_attack_complexity": nvd.get("cvss_attack_complexity"),
            "cvss_privileges_required": nvd.get("cvss_privileges_required"),
            "cvss_user_interaction": nvd.get("cvss_user_interaction"),
            "likelihood": decision.likelihood,
            "impact": decision.impact,
            "derived_risk": decision.derived_risk,
            "risk_explanation": decision.risk_explanation,
            "remediation_suggestion": decision.remediation_suggestion,
            "enriched_at": datetime.now(UTC).isoformat(),
        }
        sb.table("issues").update(_sanitize(update_row)).eq("id", issue["id"]).execute()
        return {"epss_hit": epss_score is not None, "kev_hit": in_kev}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_process_one, issue): issue for issue in issues}
        completed = 0
        for future in as_completed(futures):
            issue = futures[future]
            completed += 1
            try:
                result = future.result()
                enriched += 1
                if result.get("epss_hit"):
                    epss_hits += 1
                if result.get("kev_hit"):
                    kev_hits += 1
            except Exception as e:
                failed += 1
                if failed <= 3:
                    emit_trace(
                        run_id,
                        "sub-agent-2",
                        "ERROR",
                        f"Issue {issue.get('id')} enrichment failed "
                        f"({type(e).__name__}): {str(e)[:200]}",
                    )

            if completed % 20 == 0 and completed < len(issues):
                emit_trace(
                    run_id,
                    "sub-agent-2",
                    "MESSAGE",
                    f"Enriched {completed}/{len(issues)} issues "
                    f"({enriched} succeeded, {failed} failed so far)",
                )

    emit_trace(
        run_id,
        "sub-agent-2",
        "DONE",
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

    # Aggregate token usage from all TOKEN_USAGE trace events emitted during this run
    token_events = (
        sb.table("agent_trace_events")
        .select("payload")
        .eq("run_id", run_id)
        .eq("agent", "sub-agent-2")
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
