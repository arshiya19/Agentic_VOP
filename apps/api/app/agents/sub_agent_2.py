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
from ..services.vuln_intelligence import VulnIntelligenceService
from .llm import invoke_structured_with_retry
from .trace import emit_trace


_EPSS_API = "https://api.first.org/data/v1/epss"
_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ---------------------------------------------------------------------------
# Intelligence Service (DynamoDB) — lazy singleton
# ---------------------------------------------------------------------------
_intelligence_service: VulnIntelligenceService | None = None


def _get_intelligence_service() -> VulnIntelligenceService | None:
    """Lazy-init intelligence service. Returns None if not configured."""
    global _intelligence_service
    if (
        _intelligence_service is None
        and settings.intelligence_enabled
        and settings.intelligence_table_name
    ):
        _intelligence_service = VulnIntelligenceService(
            table_name=settings.intelligence_table_name,
            region=settings.intelligence_aws_region,
        )
    return _intelligence_service if settings.intelligence_enabled else None


# ---- MITRE projection helpers ----------------------------------------------
# Used to compute the 9 MITRE-derived columns we promote onto `issues` (added
# in migration 0020). Kept module-level so they don't get rebuilt per call.

_LIKELIHOOD_RANK = {"Low": 1, "Medium": 2, "High": 3}
_SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Very High": 4}


def _max_label(values, rank_map):
    """Return the highest-ranked label in `values` according to `rank_map`.

    Used to collapse "max likelihood across CAPECs" and "max severity across
    CAPECs" into a single text value per issue. Returns None when no labels
    in `values` are recognised.
    """
    ranks = [rank_map[v] for v in values if v in rank_map]
    if not ranks:
        return None
    target = max(ranks)
    for label, rank in rank_map.items():
        if rank == target:
            return label
    return None


# =============================================================================
# Prioritization formula — hybrid: deterministic Python score + LLM prose
# =============================================================================
# Ported from the previous chatbot-cyberisk `vop_reprio` engine and extended
# with EPSS, CISA KEV, ATT&CK tactics, and compliance-scope weighting.
#
# Output:
#   derived_risk           — 0-100 score (existing column; the formula produces
#                            a 0-10 score internally, then * 10)
#   priority               — P0..P3 banding
#   components_summary     — every factor stored as jsonb for audit
#   scoring_policy_version — version string so we can A/B test policies
# =============================================================================

SCORING_POLICY_VERSION = "reprio-v1.0"

_SEV_TO_BASE = {
    "Critical": 9.5,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 2.0,
    "Info": 0.5,
}
_ENV_WEIGHTS = {
    "production": 1.20,
    "staging": 1.00,
    "qa": 0.85,
    "development": 0.80,
    "sandbox": 0.70,
}
_CRIT_WEIGHTS = {5: 1.20, 4: 1.10, 3: 1.00, 2: 0.95, 1: 0.90}
_DATA_CLASS_WEIGHTS = {
    "restricted": 1.20,
    "confidential": 1.10,
    "internal": 1.00,
    "public": 0.90,
}
_EXPOSURE_WEIGHTS = {"public": 1.15, "internal": 1.00}
_AV_WEIGHTS = {
    "NETWORK": 1.20,
    "ADJACENT": 1.10,
    "LOCAL": 1.00,
    "PHYSICAL": 0.90,
}
_CWE_LIKELIHOOD_WEIGHTS = {"High": 1.10, "Medium": 1.00, "Low": 0.95}

# ATT&CK tactic bonuses applied additively to the tactic factor
_TACTIC_BONUSES = {
    "initial-access": 0.08,
    "execution": 0.05,
    "privilege-escalation": 0.05,
    "lateral-movement": 0.04,
    "exfiltration": 0.04,
}

# KEV-listed findings get bumped to at least this 0-10 score (== priority P1+).
_KEV_FLOOR = 8.5


def _compute_score(issue: dict, asset: dict | None) -> dict:
    """Deterministic risk-score formula.

    Args:
      issue: row from `issues` table (or partial dict with the scoring inputs).
      asset: row from `assets` table (or None when the issue is unattributed).

    Returns:
      {
        'derived_risk':           0-100 score,
        'priority':               'P0' | 'P1' | 'P2' | 'P3',
        'components_summary':     {...all factors used...},
        'scoring_policy_version': 'reprio-v1.0',
      }

    Pure function — no DB calls, no LLM, no side effects. Same input always
    produces the same output.
    """
    a = asset or {}

    # --- Base score: CVSS if present, else severity-mapped, else mid-range
    base = issue.get("cvss_score") or _SEV_TO_BASE.get(issue.get("severity"), 5.0)
    base = float(base)

    # --- Asset-context multipliers (default 1.0 when asset is unattributed)
    env_f = _ENV_WEIGHTS.get(a.get("environment"), 1.00)
    crit_f = _CRIT_WEIGHTS.get(a.get("business_criticality"), 1.00)
    data_f = _DATA_CLASS_WEIGHTS.get(a.get("data_classification"), 1.00)
    exposure_f = _EXPOSURE_WEIGHTS.get(a.get("exposure"), 1.00)

    # --- Threat-intel multipliers
    av_f = _AV_WEIGHTS.get(issue.get("cvss_attack_vector"), 1.00)
    cwe_f = _CWE_LIKELIHOOD_WEIGHTS.get(issue.get("cwe_likelihood_of_exploit"), 1.00)

    # EPSS: scale 0..1 → 0.9..1.25 (higher EPSS = stronger boost)
    epss = float(issue.get("epss_score") or 0)
    epss_f = round(0.9 + epss * 0.35, 4)

    # ATT&CK tactics: additive bonuses for high-impact tactics
    tactics = issue.get("attack_tactics") or []
    tactic_f = 1.00
    for tactic, bonus in _TACTIC_BONUSES.items():
        if tactic in tactics:
            tactic_f += bonus
    tactic_f = round(tactic_f, 4)

    # Compliance scope: each compliance tag adds 5% (so PCI+SOC2 = 1.10)
    compliance_tags = a.get("compliance_tags") or []
    compliance_f = round(1.00 + 0.05 * len(compliance_tags), 4)

    # --- Combine
    raw_score = (
        base
        * env_f
        * crit_f
        * data_f
        * exposure_f
        * av_f
        * cwe_f
        * epss_f
        * tactic_f
        * compliance_f
    )

    # --- KEV floor (CISA-listed actively-exploited)
    kev_floor_applied = False
    if issue.get("exploit_in_kev"):
        if raw_score < _KEV_FLOOR:
            raw_score = _KEV_FLOOR
            kev_floor_applied = True

    # --- Clamp to 0..9.9 then scale to 0..99 for the existing column shape.
    # We deliberately cap below 10.0 (max display 99, not 100) because a score
    # of exactly 100 implies certainty / theoretical maximum, which doesn't
    # match how security risk actually behaves — there's always residual
    # uncertainty. Industry convention (Tenable, Qualys, ArmorCode) caps the
    # public-facing score below the formula maximum.
    clamped_score = round(max(0.0, min(9.9, raw_score)), 1)
    derived_risk = round(clamped_score * 10, 2)

    # --- Priority banding (matches the old repo's P0..P3 model)
    if clamped_score >= 9.0:
        priority = "P0"
    elif clamped_score >= 7.0:
        priority = "P1"
    elif clamped_score >= 4.0:
        priority = "P2"
    else:
        priority = "P3"

    components_summary = {
        "base": round(base, 2),
        "env_f": env_f,
        "crit_f": crit_f,
        "data_f": data_f,
        "exposure_f": exposure_f,
        "av_f": av_f,
        "cwe_f": cwe_f,
        "epss_f": epss_f,
        "tactic_f": tactic_f,
        "compliance_f": compliance_f,
        "kev_floor_applied": kev_floor_applied,
        "raw_score": round(raw_score, 3),
        "clamped_score": clamped_score,
    }

    return {
        "derived_risk": derived_risk,
        "priority": priority,
        "components_summary": components_summary,
        "scoring_policy_version": SCORING_POLICY_VERSION,
    }


def _build_asset_index(assets: list[dict]) -> dict:
    """Build O(1) lookup dicts for asset attribution.

    Indexes by:
      - canonical name + each alias            (project / repo / direct names)
      - hostname                               (host scanners)
      - ip_address                             (host scanners)
      - (ecosystem, package_name)              (SBOM — package scanners)

    The SBOM index is the primary path for package-level findings (OSV, Trivy,
    Snyk, Dependabot). It lets a scanner emit just `{name: lodash, ecosystem: npm}`
    and the matcher finds the asset whose `dependencies.npm` contains `lodash`
    — no per-scanner alias tables needed.
    """
    by_name_or_alias: dict[str, dict] = {}
    by_hostname: dict[str, dict] = {}
    by_ip: dict[str, dict] = {}
    by_sbom: dict[tuple[str, str], dict] = {}

    for a in assets:
        if a.get("name"):
            by_name_or_alias[a["name"]] = a
        for alias in a.get("aliases") or []:
            by_name_or_alias[alias] = a
        if a.get("hostname"):
            by_hostname[a["hostname"]] = a
        if a.get("ip_address"):
            by_ip[a["ip_address"]] = a
        for ecosystem, pkgs in (a.get("dependencies") or {}).items():
            for pkg in pkgs or []:
                by_sbom[(ecosystem.lower(), pkg.lower())] = a

    return {
        "name_or_alias": by_name_or_alias,
        "hostname": by_hostname,
        "ip_address": by_ip,
        "sbom": by_sbom,
    }


def _resolve_asset(issue: dict, asset_index: dict) -> dict | None:
    """Match one issue's asset_identity (+ package field) to a row in `assets`.

    Priority chain (first match wins):
      1. Direct asset identifier (project / repo)         → name / aliases
      2. SBOM match (ecosystem + package name)            → assets.dependencies
      3. Package-name-only fallback (no ecosystem known)  → aliases
      4. Host identifiers (hostname / ipv4)               → hostname / ip_address

    SBOM matching (step 2) is the scalable path for package scanners. Each
    asset declares its dependencies once in `assets.dependencies`; every
    package-level scanner (OSV, Trivy, Snyk, Dependabot) auto-attributes
    without scanner-specific configuration.

    Returns None when nothing matches (the issue stays "unattributed" and
    the formula uses default 1.0 multipliers for all asset-context factors).
    """
    ai = issue.get("asset_identity") or {}
    pkg_obj = issue.get("package") or {}
    name_or_alias = asset_index["name_or_alias"]

    # 1. Direct asset identifiers — strongest signal
    for key in ("project", "repo"):
        v = ai.get(key)
        if v and v in name_or_alias:
            return name_or_alias[v]

    # Package name + ecosystem can live in either `asset_identity` (Trivy's
    # PkgName / package_name) or the dedicated `package` field (OSV-style).
    pkg_name = (
        ai.get("PkgName")
        or ai.get("package_name")
        or pkg_obj.get("name")
        or pkg_obj.get("package_name")
    )
    ecosystem = ai.get("ecosystem") or pkg_obj.get("ecosystem") or pkg_obj.get("type")

    # 2. SBOM match — precise when ecosystem is known
    if pkg_name and ecosystem:
        key = (ecosystem.lower(), pkg_name.lower())
        if key in asset_index["sbom"]:
            return asset_index["sbom"][key]

    # 3. Package-name-only fallback via aliases (when ecosystem missing)
    if pkg_name and pkg_name in name_or_alias:
        return name_or_alias[pkg_name]

    # 4. Host identifiers
    hostname = ai.get("hostname")
    if hostname and hostname in asset_index["hostname"]:
        return asset_index["hostname"][hostname]

    ip = ai.get("ipv4")
    if ip and ip in asset_index["ip_address"]:
        return asset_index["ip_address"][ip]

    return None


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
    asset: dict | None = None,
    scoring: dict | None = None,
) -> LLMEnrichmentDecision:
    """Call the LLM to produce the prose narrative for an already-scored issue.

    Tiered retry — escalate temperature first, then escalate the model on the
    final attempt for issues the small model can't reason about.

    As of prompt v1.4, the LLM does NOT compute the score. The deterministic
    formula `_compute_score()` produces derived_risk/priority/components_summary
    before this call; we pass them to the LLM as additional context so the
    explanation can cite the ACTUAL factors that drove the number.

    `mitre` is the full MITRE chain payload —
        {"cwe": {...} | {}, "capec": [...], "attack": [...]}
    `asset` is the resolved asset row (or None for unattributed findings).
    `scoring` is the formula's output (derived_risk, priority, components).
    Any may be empty/None — the prompt handles missing sections gracefully.
    """
    params = prompt_row.get("parameters") or {}
    base_temp = float(params.get("temperature", 0.2))
    max_tokens = int(params.get("max_tokens", 500))
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
            "asset": _asset_for_llm(asset),
        },
        "scoring": {
            "derived_risk": (scoring or {}).get("derived_risk"),
            "priority": (scoring or {}).get("priority"),
            "policy_version": (scoring or {}).get("scoring_policy_version"),
            "components": (scoring or {}).get("components_summary") or {},
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


def _asset_for_llm(asset: dict | None) -> dict:
    """Trim an asset row to the fields useful for explanation prose.

    We DON'T pass every column (description, repo_url, etc. would just bloat
    tokens). The LLM cares about the categorical signals — env, exposure,
    criticality, compliance — same ones the formula uses.
    """
    if not asset:
        return {}
    return {
        "name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "environment": asset.get("environment"),
        "exposure": asset.get("exposure"),
        "business_criticality": asset.get("business_criticality"),
        "data_classification": asset.get("data_classification"),
        "compliance_tags": asset.get("compliance_tags") or [],
        "network_zone": asset.get("network_zone"),
        "business_owner": asset.get("business_owner"),
    }


def _fetch_nvd_data_from_intelligence(
    cve_ids: list[str], run_id: str | None = None
) -> dict[str, dict]:
    """Fetch NVD data using the DynamoDB Intelligence Service (fast path).

    Returns the same dict shape as _fetch_nvd_data so it's a drop-in replacement.
    Handles batching internally — callers may pass more than 100 CVE IDs.
    """
    svc = _get_intelligence_service()
    if svc is None:
        return {}

    results: dict[str, dict] = {}
    try:
        # DynamoDB BatchGetItem supports max 100 keys per call. Chunk the input
        # so we don't silently drop CVEs beyond the first 100.
        all_cve_ids = list(cve_ids)
        for i in range(0, len(all_cve_ids), 100):
            chunk = all_cve_ids[i : i + 100]
            intel_map = svc.batch_get_cve_intelligence(chunk)
            for cve_id, intel in intel_map.items():
                if intel and intel.resolution == "resolved" and intel.nvd:
                    results[cve_id] = {
                        "cwe_id": intel.nvd.cwe_ids[0] if intel.nvd.cwe_ids else None,
                        "cvss_score": intel.nvd.cvss_v31_score,
                        "cvss_version": "3.1" if intel.nvd.cvss_v31_score is not None else None,
                        "cvss_vector": intel.nvd.cvss_v31_vector,
                        "cvss_attack_vector": intel.nvd.cvss_attack_vector,
                        "cvss_attack_complexity": intel.nvd.cvss_attack_complexity,
                        "cvss_privileges_required": intel.nvd.cvss_privileges_required,
                        "cvss_user_interaction": intel.nvd.cvss_user_interaction,
                    }
    except Exception as e:
        if run_id:
            emit_trace(
                run_id,
                "sub-agent-2",
                "ERROR",
                f"Intelligence service lookup failed: {type(e).__name__}: {str(e)[:200]}",
            )

    return results


def _write_back_nvd_to_dynamo(raw_responses: list[dict], run_id: str | None = None) -> None:
    """Write already-fetched raw NVD API vulnerability objects back to DynamoDB.

    Accepts raw NVD responses captured during the fallback fetch (avoids
    duplicate API calls). Errors are logged but never raised — write-back
    is best-effort and must not block enrichment.
    """
    svc = _get_intelligence_service()
    if svc is None:
        return

    try:
        written = svc.write_back_cves(raw_responses)
        if run_id:
            emit_trace(
                run_id,
                "sub-agent-2",
                "MESSAGE",
                f"Write-back: stored {written} CVE(s) in DynamoDB for future cache hits",
            )
    except Exception as e:
        if run_id:
            emit_trace(
                run_id,
                "sub-agent-2",
                "ERROR",
                f"Write-back to DynamoDB failed: {type(e).__name__}: {str(e)[:200]}",
            )


def _parse_nvd_response(vulns: list[dict]) -> dict:
    """Extract CWE + CVSS fields from an NVD API response's vulnerabilities list.

    Pure parsing — no HTTP, no side-effects.
    """
    if not vulns:
        return {}

    cve_data = vulns[0].get("cve", {}) or {}
    metrics = cve_data.get("metrics", {}) or {}

    # Prefer CVSS v3.1, fall back to v3.0
    cvss: dict | None = None
    cvss_version_picked: str | None = None
    for m in metrics.get("cvssMetricV31", []) or []:
        if m.get("type") == "Primary":
            cvss = m.get("cvssData") or {}
            cvss_version_picked = "3.1"
            break
    if cvss is None:
        for m in metrics.get("cvssMetricV30", []) or []:
            if m.get("type") == "Primary":
                cvss = m.get("cvssData") or {}
                cvss_version_picked = "3.0"
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

    base_score = (cvss or {}).get("baseScore")
    vector_string = (cvss or {}).get("vectorString")

    return {
        "cwe_id": cwe_id,
        "cvss_score": float(base_score) if base_score is not None else None,
        "cvss_version": cvss_version_picked,
        "cvss_vector": vector_string,
        "cvss_attack_vector": (cvss or {}).get("attackVector"),
        "cvss_attack_complexity": (cvss or {}).get("attackComplexity"),
        "cvss_privileges_required": (cvss or {}).get("privilegesRequired"),
        "cvss_user_interaction": (cvss or {}).get("userInteraction"),
    }


# Circuit breaker threshold — after this many consecutive NVD failures,
# stop attempting remaining CVEs and record them as missed.
_CIRCUIT_BREAKER_THRESHOLD = 5


def _fetch_nvd_data(
    cve_ids: list[str],
    api_key: str | None,
    run_id: str | None = None,
    *,
    collect_raw: list[dict] | None = None,
    collect_missed: list[str] | None = None,
) -> dict[str, dict]:
    """For each CVE, fetch NVD data: CWE id + CVSS v3 vector breakdown.

    Throttle math (NVD's published rolling 30s window):
      with key   : 50 req / 30s  →  0.6s between calls
      without key: 5  req / 30s  →  6.0s between calls

    Padded by 10% so a clock-skew burst between us and NVD's counter
    doesn't tip us over the limit. Sequential — no parallelism — so the
    pace is the only thing keeping us under the limit.

    Circuit breaker: after `_CIRCUIT_BREAKER_THRESHOLD` consecutive failures,
    the loop stops early and remaining CVE IDs are appended to `collect_missed`
    (if provided). This avoids spending minutes hammering a degraded/down API.

    If `collect_raw` is provided (a list), raw NVD vulnerability objects
    are appended to it for downstream write-back to DynamoDB.

    If `collect_missed` is provided (a list), CVE IDs that could not be
    fetched (individual failures + circuit-breaker skipped) are appended.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    delay = 0.66 if api_key else 6.6

    # Filter to actual CVE-* IDs. NVD's API only recognizes CVE-YYYY-NNN — sending
    # PYSEC/GHSA/RUSTSEC/OSV ids yields 404s that look like outages in the trace.
    # OSV advisories often have a non-CVE primary id with no CVE alias (the
    # advisory was never assigned a CVE), so dropping them here is the only
    # honest option — there's nothing for NVD to return.
    cve_ids = [c for c in cve_ids if c and c.upper().startswith("CVE-")]

    if run_id:
        sample = [repr(c) for c in cve_ids[:5]]
        emit_trace(
            run_id,
            "sub-agent-2",
            "MESSAGE",
            f"NVD handoff: count={len(cve_ids)} api_key={'SET' if api_key else 'MISSING'} "
            f"sample={sample}",
        )

    results: dict[str, dict] = {}
    consecutive_failures = 0

    with httpx.Client(timeout=30, headers=headers) as client:
        for cve in cve_ids:
            # --- Circuit breaker: stop if NVD is consistently failing ---
            if consecutive_failures >= _CIRCUIT_BREAKER_THRESHOLD:
                remaining = [c for c in cve_ids if c not in results and c != cve]
                remaining.insert(0, cve)
                if collect_missed is not None:
                    collect_missed.extend(remaining)
                if run_id:
                    emit_trace(
                        run_id,
                        "sub-agent-2",
                        "MESSAGE",
                        f"Circuit breaker open — {consecutive_failures} consecutive NVD "
                        f"failures. Skipping remaining {len(remaining)} CVE(s) for "
                        f"deferred retry.",
                    )
                break

            try:
                resp = request_with_retry(
                    client,
                    "GET",
                    _NVD_API,
                    params={"cveId": cve},
                    timeout=30,
                    max_attempts=5,
                    backoff_factor=2.0,
                    run_id=run_id,
                    agent="sub-agent-2",
                )
                vulns = resp.json().get("vulnerabilities", []) or []
                if not vulns:
                    time.sleep(delay)
                    continue

                # Collect raw response for write-back if requested
                if collect_raw is not None:
                    collect_raw.append(vulns[0])

                parsed = _parse_nvd_response(vulns)
                if parsed:
                    results[cve] = parsed

                # Success — reset circuit breaker counter
                consecutive_failures = 0
            except Exception:  # nosec B110 — intentional: skip individual CVE NVD fetch failures, continue to next CVE  # noqa: S110
                consecutive_failures += 1
                if collect_missed is not None:
                    collect_missed.append(cve)
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

    # 1b. Batch-load the assets table so the formula has business context
    # available for every issue. One query feeds all subsequent issue lookups.
    asset_rows = sb.table("assets").select("*").execute().data or []
    asset_index = _build_asset_index(asset_rows)
    emit_trace(
        run_id,
        "sub-agent-2",
        "MESSAGE",
        f"Loaded {len(asset_rows)} asset rows for scoring context",
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
        if settings.intelligence_enabled:
            # Fast path: DynamoDB Intelligence Service
            emit_trace(
                run_id, "sub-agent-2", "MESSAGE", "Querying Intelligence Service (DynamoDB)…"
            )
            try:
                nvd_data = _fetch_nvd_data_from_intelligence(list(cve_ids), run_id=run_id)
                emit_trace(
                    run_id,
                    "sub-agent-2",
                    "MESSAGE",
                    f"Intelligence Service returned data for {len(nvd_data)} CVE(s)",
                )
            except Exception as e:
                emit_trace(
                    run_id,
                    "sub-agent-2",
                    "ERROR",
                    f"Intelligence Service lookup failed, falling back to NVD API: {type(e).__name__}: {str(e)[:200]}",
                )
                # Fall through to NVD API fallback below
                nvd_data = {}

            # Fallback: for CVEs not found in DynamoDB, query NVD API directly
            # and write the results back to DynamoDB for future cache hits.
            missed_cves = [cve for cve in cve_ids if cve not in nvd_data]
            if missed_cves:
                nvd_key = settings.nvd_api_key or None
                speed_note = (
                    f"with API key (~{len(missed_cves) * 0.66:.0f}s expected, "
                    f"plus retries on NVD 429/503)"
                    if nvd_key
                    else f"no API key — rate-limited (~{len(missed_cves) * 6.6:.0f}s expected, "
                    f"plus retries)"
                )
                emit_trace(
                    run_id,
                    "sub-agent-2",
                    "MESSAGE",
                    f"Falling back to NVD API for {len(missed_cves)} "
                    f"cache-missed CVE(s) ({speed_note})…",
                )
                try:
                    raw_nvd_responses: list[dict] = []
                    nvd_missed: list[str] = []
                    fallback_data = _fetch_nvd_data(
                        missed_cves,
                        nvd_key,
                        run_id=run_id,
                        collect_raw=raw_nvd_responses,
                        collect_missed=nvd_missed,
                    )
                    nvd_data.update(fallback_data)
                    emit_trace(
                        run_id,
                        "sub-agent-2",
                        "MESSAGE",
                        f"NVD API fallback returned data for {len(fallback_data)} CVE(s)"
                        + (
                            f" — {len(nvd_missed)} CVE(s) deferred (circuit breaker / failures)"
                            if nvd_missed
                            else ""
                        ),
                    )

                    # Write-back: store NVD API results into DynamoDB so
                    # future scans don't miss the same CVEs.
                    if raw_nvd_responses:
                        _write_back_nvd_to_dynamo(raw_nvd_responses, run_id=run_id)
                except Exception as e:
                    emit_trace(
                        run_id,
                        "sub-agent-2",
                        "ERROR",
                        f"NVD API fallback failed: {type(e).__name__}: {str(e)[:200]}",
                    )
        else:
            # Legacy path: Direct NVD API calls (rate-limited)
            nvd_key = settings.nvd_api_key or None
            speed_note = (
                f"with API key (~{len(cve_ids) * 0.66:.0f}s expected)"
                if nvd_key
                else f"no API key — rate-limited (~{len(cve_ids) * 6.6:.0f}s expected)"
            )
            emit_trace(run_id, "sub-agent-2", "MESSAGE", f"Querying NVD ({speed_note})…")
            try:
                nvd_missed_legacy: list[str] = []
                nvd_data = _fetch_nvd_data(
                    list(cve_ids),
                    nvd_key,
                    run_id=run_id,
                    collect_missed=nvd_missed_legacy,
                )
                emit_trace(
                    run_id,
                    "sub-agent-2",
                    "MESSAGE",
                    f"NVD returned data for {len(nvd_data)} CVE(s)"
                    + (
                        f" — {len(nvd_missed_legacy)} CVE(s) deferred (circuit breaker / failures)"
                        if nvd_missed_legacy
                        else ""
                    ),
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

        # ---- MITRE projection columns (added in migration 0020) ----
        # Compute the 9 denormalized columns from the chain payload so the
        # prioritization + remediation engines can query without joining
        # back to the catalog tables on every read.
        cwe_likelihood = (cwe_row or {}).get("likelihood_of_exploit")
        cwe_abstraction = (cwe_row or {}).get("abstraction")
        # Dedupe + sort the mitigation phases across all CWE mitigations.
        mitigation_phases = sorted(
            {
                phase
                for m in (cwe_row or {}).get("mitigations") or []
                for phase in (m.get("phase") or [])
                if phase
            }
        )
        capec_ids_list = list((cwe_row or {}).get("related_capec") or [])
        capec_max_likelihood = _max_label(
            [cr.get("likelihood_of_attack") for cr in capec_rows], _LIKELIHOOD_RANK
        )
        capec_max_severity = _max_label(
            [cr.get("typical_severity") for cr in capec_rows], _SEVERITY_RANK
        )
        attack_tech_ids = sorted(
            {ar["technique_id"] for ar in attack_rows if ar.get("technique_id")}
        )
        attack_tactics_list = sorted({t for ar in attack_rows for t in (ar.get("tactics") or [])})
        attack_platforms_list = sorted(
            {p for ar in attack_rows for p in (ar.get("platforms") or [])}
        )

        # ---- Hybrid scoring (formula + LLM-for-prose) ----
        # 1. Resolve asset via the same priority chain as issue_with_asset view.
        asset = _resolve_asset(issue, asset_index)

        # 2. Build a snapshot of the issue augmented with MITRE projection
        #    fields, so _compute_score sees the final state the row will have.
        issue_for_scoring = {
            **issue,
            "epss_score": epss_score,
            "exploit_in_kev": in_kev,
            "cvss_attack_vector": nvd.get("cvss_attack_vector"),
            "cwe_likelihood_of_exploit": cwe_likelihood,
            "attack_tactics": attack_tactics_list,
        }
        scoring = _compute_score(issue_for_scoring, asset)

        # 3. LLM gets the computed score + factors and writes only the prose.
        decision = _llm_decide(
            run_id, prompt_row, issue, epss, nvd, in_kev, mitre_payload, asset, scoring
        )

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
            # ---- Asset-context snapshot (denormalized from assets table) ----
            # Mirrors the vestigial columns originally specced in 0001. Lets
            # SQL queries read asset context without joining. Snapshot is fresh
            # for each enrichment run; if asset metadata changes later, the
            # issue's snapshot stays as-of-this-run until the next rescore.
            "exposure": (asset or {}).get("exposure"),
            "business_criticality": (asset or {}).get("business_criticality"),
            "asset_owner": (asset or {}).get("business_owner"),
            # ---- Formula-computed scoring (migration 0022) ----
            "derived_risk": scoring["derived_risk"],
            "priority": scoring["priority"],
            "components_summary": scoring["components_summary"],
            "scoring_policy_version": scoring["scoring_policy_version"],
            # ---- LLM-generated prose (prompt v1.4) ----
            "risk_explanation": decision.risk_explanation,
            "remediation_suggestion": decision.remediation_suggestion,
            "enriched_at": datetime.now(UTC).isoformat(),
            # ---- MITRE projection (migration 0020) ----
            "cwe_likelihood_of_exploit": cwe_likelihood,
            "cwe_abstraction": cwe_abstraction,
            "cwe_mitigation_phases": mitigation_phases,
            "capec_ids": capec_ids_list,
            "capec_max_likelihood_of_attack": capec_max_likelihood,
            "capec_max_typical_severity": capec_max_severity,
            "attack_technique_ids": attack_tech_ids,
            "attack_tactics": attack_tactics_list,
            "attack_platforms": attack_platforms_list,
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
