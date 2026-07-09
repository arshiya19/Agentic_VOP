"""Confidence Engine — deterministic 5-factor scoring per Phase-1 §8.

Pure Python. NO LLM. Takes (issue, asset, pattern, package) and returns
{score, components, approval_required}. Per the Phase-1 doc principle
"AI for planning, deterministic logic for operations" — the LLM writes
prose, this function owns the number.

Weights (per doc §8, sum to 100):
  - Deterministic Fix          30%
  - Blast Radius               25%
  - Test Coverage              20%
  - Rollback Availability      15%
  - Environmental Uncertainty  10%

Each factor returns a contribution (0..weight) plus a one-line reason for
why it scored that way. The reasons are surfaced in the UI so users can see
WHY a package scored 85 vs 100.
"""

from __future__ import annotations

import math
from typing import Any

from ...models import RemediationPathway


# ---------------------------------------------------------------------------
# Per-factor scorers
# ---------------------------------------------------------------------------

_DETERMINISTIC_ACTIONS = {
    "configuration_change",
    "package_upgrade",
    "dependency_upgrade",
    "certificate_renewal",
    "secret_rotation",
    "iam_policy_fix",
    "network_policy_change",
    "access_removal",
}


def _score_deterministic_fix(pattern: dict) -> tuple[int, str]:
    """30 if the fix is a config/package flip; 20 for code changes (pattern
    exists but human implementation needed); 10 otherwise."""
    action = pattern.get("action_type") or ""
    if action in _DETERMINISTIC_ACTIONS:
        return 30, f"{action} — fully deterministic (clean target version / config flip)"
    if action == "code_change":
        return 20, "code_change — pattern is well-known but requires developer implementation"
    return 10, f"action_type={action!r} has no canonical automated fix path"


def _score_blast_radius(affected_asset_count: int) -> tuple[int, str]:
    """25 for a single affected asset; log-scaled down for many."""
    n = max(1, int(affected_asset_count))
    if n == 1:
        return 25, "1 affected asset — change is contained"
    # 25 → 20 (10 assets), 25 → 15 (100), 25 → 10 (1000)
    score = max(0, round(25 - 5 * math.log10(n)))
    return score, f"{n} affected assets — wider blast radius"


def _score_test_coverage(pathway: RemediationPathway) -> tuple[int, str]:
    """20 if the pathway has ≥2 validation tests (counted post-LLM-generation)."""
    n = len(pathway.validation_tests)
    if n >= 2:
        return 20, f"{n} validation tests generated"
    if n == 1:
        return 12, "1 validation test — partial coverage"
    return 0, "no validation tests"


def _score_rollback_availability(pattern: dict, pathway: RemediationPathway) -> tuple[int, str]:
    """15 / 10 / 5 / 0 by rollback strategy, downgraded if the pathway's
    own RollbackPlan reports supported=false (i.e. the LLM determined
    rollback isn't safe for THIS specific finding).
    """
    if not pathway.rollback_plan.supported:
        return 0, "rollback not supported for this specific finding"
    strategy = pattern.get("rollback_strategy") or "not_applicable"
    mapping = {
        "automatic": (15, "automatic rollback — fully reversible without redeploy"),
        "redeploy": (10, "redeploy-based rollback — requires CI/CD round-trip"),
        "manual": (5, "manual rollback procedure — requires operator intervention"),
        "not_applicable": (0, "no rollback path defined"),
    }
    return mapping.get(strategy, (0, f"unknown rollback_strategy={strategy!r}"))


def _score_environmental_uncertainty(issue: dict, asset: dict, pattern: dict) -> tuple[int, str]:
    """10 if we know enough about the deployment context to predict the fix's
    behaviour; 5 if context is partial; 0 if completely unknown.

    Code-level / IaC families don't need runtime context — they score full
    because the fix is at the source level.
    """
    family = pattern.get("family")
    if family in {"public_exposure", "network_exposure", "injection"}:
        return 10, f"family={family} — fix is at source/config level, no runtime dependency"

    if issue.get("runtime_os_family"):
        return 10, f"runtime_os_family={issue['runtime_os_family']} — deployment platform known"

    if asset and asset.get("environment"):
        return 8, f"asset.environment={asset['environment']} known, OS family unknown"

    return 5, "no runtime platform or asset environment — uncertain deployment context"


# ---------------------------------------------------------------------------
# Approval policy
# ---------------------------------------------------------------------------


def _derive_approval(score: int, priority: str | None) -> str:
    """Map (score, priority) → approval_required.

    Policy (Phase-1):
      - P0 (Critical) finding with score < 80      → multi_stage (high-stakes, low-confidence)
      - score ≥ 90 AND priority in (P2, P3)        → auto (routine, high-confidence)
      - else                                       → single_approver (default)
    """
    priority = priority or ""
    if priority == "P0" and score < 80:
        return "multi_stage"
    if score >= 90 and priority in ("P2", "P3"):
        return "auto"
    return "single_approver"


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def compute_confidence(
    *,
    issue: dict,
    asset: dict,
    pattern: dict,
    pathway: RemediationPathway,
    affected_asset_count: int = 1,
) -> dict[str, Any]:
    """Compute the confidence score + per-factor breakdown + approval policy.

    Returns:
      {
        "score": int,                       # 0..100
        "components": {                     # per-factor reasons for UI transparency
          "deterministic_fix":          {"score": int, "max_score": int, "reason": str},
          "blast_radius":               {"score": int, "max_score": int, "reason": str},
          "test_coverage":              {"score": int, "max_score": int, "reason": str},
          "rollback_availability":      {"score": int, "max_score": int, "reason": str},
          "environmental_uncertainty":  {"score": int, "max_score": int, "reason": str},
        },
        "approval_required": "auto" | "single_approver" | "multi_stage",
      }
    """
    df_score, df_reason = _score_deterministic_fix(pattern)
    br_score, br_reason = _score_blast_radius(affected_asset_count)
    tc_score, tc_reason = _score_test_coverage(pathway)
    rb_score, rb_reason = _score_rollback_availability(pattern, pathway)
    eu_score, eu_reason = _score_environmental_uncertainty(issue, asset, pattern)

    total = df_score + br_score + tc_score + rb_score + eu_score
    total = max(0, min(100, total))

    return {
        "score": total,
        "components": {
            "deterministic_fix": {"score": df_score, "max_score": 30, "reason": df_reason},
            "blast_radius": {"score": br_score, "max_score": 25, "reason": br_reason},
            "test_coverage": {"score": tc_score, "max_score": 20, "reason": tc_reason},
            "rollback_availability": {"score": rb_score, "max_score": 15, "reason": rb_reason},
            "environmental_uncertainty": {"score": eu_score, "max_score": 10, "reason": eu_reason},
        },
        "approval_required": _derive_approval(total, issue.get("priority")),
    }


# ---------------------------------------------------------------------------
# Agentic path — no pattern available. Score from source authority + verifier
# report + asset context. Same 100-point envelope, different signals.
# ---------------------------------------------------------------------------

# Domain-tier hint list — mirrors _AGENT_AUTHORITATIVE_HOSTS in planner.py.
# Kept as a local copy to avoid a circular import (planner imports confidence).
# WHEN ADDING A DOMAIN, ADD IT TO BOTH SETS.
_AUTHORITATIVE_HOSTS = {
    # --- Cloud provider primary docs (Tier 1) ---
    "docs.aws.amazon.com",
    "aws.amazon.com",
    "docs.microsoft.com",
    "learn.microsoft.com",
    "cloud.google.com",
    "docs.oracle.com",
    # --- Standards bodies + governments (Tier 1) ---
    "cisecurity.org",
    "nvd.nist.gov",
    "csrc.nist.gov",
    "cisa.gov",
    "www.cisa.gov",
    "cwe.mitre.org",
    "capec.mitre.org",
    "attack.mitre.org",
    "cve.mitre.org",
    # --- Core project + community docs (Tier 2) ---
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "kubernetes.io",
    "docs.kubernetes.io",
    "docs.docker.com",
    "developer.hashicorp.com",
    "hashicorp.com",
    "registry.terraform.io",
    "cert.org",
    "us-cert.gov",
    # --- Scanner vendor docs — canonical source for the findings we ingest ---
    "docs.prismacloud.io",
    "docs.paloaltonetworks.com",  # Checkov / Prisma Cloud
    "avd.aquasec.com",
    "docs.aquasec.com",
    "aquasec.com",  # Trivy (Aqua Vulnerability DB)
    "snyk.io",
    "security.snyk.io",
    "docs.snyk.io",  # Snyk
    "docs.wiz.io",  # Wiz
    "docs.tenable.com",  # Tenable / Nessus
    "www.qualys.com",
    "qualys.com",  # Qualys
    "docs.github.com",
    "github.com",  # GitHub advisories / security tab
    # --- OS-vendor security trackers (canonical for os_vulnerability family) ---
    "access.redhat.com",
    "ubuntu.com",
    "security-tracker.debian.org",
    "usn.ubuntu.com",
    "www.suse.com",
    # --- Language ecosystem advisory databases (canonical for vulnerable_dependency) ---
    "advisories.dependabot.com",
    "osv.dev",
    "python.org",
    "docs.python.org",
    "pypi.org",
    "nodejs.org",
    "npmjs.com",
    "maven.apache.org",
    "central.sonatype.com",
    "rubygems.org",
    "packagist.org",
}


def _extract_hosts_from_pathway(pathway: RemediationPathway) -> list[str]:
    """All distinct hostnames the agent cited across steps + rollback + tests."""
    from urllib.parse import urlparse

    urls: set[str] = set()

    def _add(source_url):
        if not source_url:
            return
        try:
            host = urlparse(source_url).netloc.lower()
            if host:
                urls.add(host)
        except Exception:  # noqa: BLE001, S110 — malformed URL, ignore
            pass

    for step in pathway.remediation_steps or []:
        _add(getattr(step, "source_url", None))
    if pathway.rollback_plan and pathway.rollback_plan.steps:
        for step in pathway.rollback_plan.steps:
            _add(getattr(step, "source_url", None))
    return sorted(urls)


def compute_confidence_agentic(
    issue: dict,
    asset: dict,
    pathway: RemediationPathway,
    verification_report,  # verifier.VerificationReport (avoid circular import)
) -> dict[str, Any]:
    """Confidence for agent-produced packages.

    Same 100-point envelope as compute_confidence, different signals — we
    don't have a pattern.action_type / pattern.confidence_base to anchor
    on, so we derive from what the agent + verifier actually observed.

    Factors (total = 100):
      Source Authority         30% — Tier-1/2 URLs cited across the pathway
      Cross-Source Consensus   25% — ratio of commands independently verified
      Verification Cleanliness 20% — penalty for placeholders / destructive /
                                    low-authority findings from the verifier
      Depth Adequacy           15% — penalty for per-family depth shortfalls
      Environmental            10% — asset context (prod / critical / public)
    """
    # --- 1. Source Authority (30) ---
    # Include verifier's cross-verification URLs — they're independent sources
    # the verifier's targeted search surfaced, and count as authority signal.
    from urllib.parse import urlparse

    pathway_hosts = set(_extract_hosts_from_pathway(pathway))
    verifier_hosts: set[str] = set()
    if verification_report and verification_report.verification_urls:
        for u in verification_report.verification_urls:
            try:
                h = urlparse(u).netloc.lower()
                if h:
                    verifier_hosts.add(h)
            except Exception:  # noqa: BLE001, S110 — malformed URL, ignore
                pass
    all_hosts = pathway_hosts | verifier_hosts
    tier12_count = sum(1 for h in all_hosts if h in _AUTHORITATIVE_HOSTS)
    other_count = len(all_hosts) - tier12_count
    # 10 per Tier-1/2 host up to 24, +2 per other host up to 6, capped at 30
    sa_score = min(30, tier12_count * 10 + min(6, other_count * 2))
    sa_reason = (
        f"{tier12_count} authoritative source(s) + {other_count} additional. "
        f"Hosts: {', '.join(sorted(all_hosts)[:5]) or 'none'}"
    )

    # --- 2. Cross-Source Consensus (25) ---
    r = verification_report
    total_examined = r.total_commands_examined if r else 0
    verified = r.cross_verified if r else 0
    if total_examined:
        ratio = verified / total_examined
        cs_score = int(25 * ratio)
        cs_reason = f"{verified}/{total_examined} critical commands cross-verified"
    else:
        cs_score = 12  # neutral if nothing was verifiable (e.g. no commands to check)
        cs_reason = "No verifiable commands (may indicate low-detail package)"

    # --- 3. Verification Cleanliness (20) ---
    penalty = 0
    reasons: list[str] = []
    if r:
        ph = len(r.placeholder_flags)
        de = len([f for f in r.destructive_flags if f["severity"] in ("critical", "high")])
        la = len(r.low_authority_flags)
        if ph:
            penalty += ph * 10
            reasons.append(f"{ph} unfilled placeholder(s)")
        if de:
            penalty += de * 3
            reasons.append(f"{de} high-severity destructive command(s)")
        if la:
            penalty += la * 5
            reasons.append(f"{la} low-authority source(s)")
    vc_score = max(0, 20 - penalty)
    vc_reason = "Clean scan — no verifier flags" if not reasons else "; ".join(reasons)

    # --- 4. Depth Adequacy (15) ---
    depth_penalty = 0
    if r:
        depth_penalty = min(15, len(r.depth_flags) * 5)
    da_score = max(0, 15 - depth_penalty)
    da_reason = (
        f"{len(r.depth_flags)} depth shortfall(s)"
        if r and r.depth_flags
        else "Meets per-family minimum depths"
    )

    # --- 5. Environmental (10) ---
    eu_score = 10
    eu_notes: list[str] = []
    if asset:
        env = (asset.get("environment") or "").lower()
        crit = asset.get("business_criticality")
        exp = (asset.get("exposure") or "").lower()
        if env == "production":
            eu_score -= 3
            eu_notes.append("production")
        if isinstance(crit, int) and crit >= 5:
            eu_score -= 2
            eu_notes.append("crown-jewel")
        if exp == "public":
            eu_score -= 2
            eu_notes.append("public-facing")
    eu_score = max(0, eu_score)
    eu_reason = (
        "Low-risk env"
        if not eu_notes
        else f"Higher-risk env ({', '.join(eu_notes)}) — penalizes confidence"
    )

    total = sa_score + cs_score + vc_score + da_score + eu_score
    total = max(0, min(100, total))

    return {
        "score": total,
        "components": {
            "source_authority": {"score": sa_score, "max_score": 30, "reason": sa_reason},
            "consensus": {"score": cs_score, "max_score": 25, "reason": cs_reason},
            "verification_cleanliness": {"score": vc_score, "max_score": 20, "reason": vc_reason},
            "depth_adequacy": {"score": da_score, "max_score": 15, "reason": da_reason},
            "environmental": {"score": eu_score, "max_score": 10, "reason": eu_reason},
        },
        "approval_required": _derive_approval(total, issue.get("priority")),
    }
