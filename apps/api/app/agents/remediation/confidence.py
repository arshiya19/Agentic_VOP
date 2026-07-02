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
