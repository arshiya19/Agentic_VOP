"""SA-3 Prompt Router — pick the right prompt for (source, family).

The master SA-3 agent is intentionally lightweight: it doesn't run an LLM
of its own. It just looks up the most-specific prompt available in
`prompt_db` and hands it to the planner. Fallback chain:

    1. sub-agent-3-{source}-{family}   e.g. sub-agent-3-trivy-os-os_vulnerability
    2. sub-agent-3-{source}            e.g. sub-agent-3-trivy-os
    3. sub-agent-3-{family}            e.g. sub-agent-3-os_vulnerability
    4. sub-agent-3                     the existing generic prompt (unchanged)

If a specialized prompt isn't seeded, behavior falls through to the current
generic prompt — this is why the router can ship BEFORE any specialized
prompts exist without changing anything today.

Why route by (source, family) instead of just family?
    Two scanners in the same family can produce structurally different
    findings. Trivy OS emits `PkgName + InstalledVersion + FixedVersion`
    for apt packages; Qualys emits KB advisories with different fields.
    A source-specific prompt can encode those field names literally in
    the prompt without generic-ifying it into paste.
"""

from __future__ import annotations

from typing import Any


# =============================================================================
# Source slug normalization
# =============================================================================
# Some connectors use dashes in the source name (`trivy-os`, `trivy-image`)
# which is fine for prompt_db.agent. Others might send `Checkov`, `trivy_os`,
# etc. — normalize before lookup so callers don't have to think about it.
#
# Deployment-tier suffixes (-ec2, -on-prem, -cloud) are stripped so the same
# prompt handles both deployment shapes. This mirrors the classifier's
# _canonical_source() logic. Without this, `trivy-image-ec2` and `trivy-image`
# would need separate prompts.
_DEPLOYMENT_SUFFIXES = ("-ec2", "-on-prem", "-onprem", "-cloud", "-cspm", "-saas")


def _slug(source: str | None) -> str:
    if not source:
        return ""
    s = source.strip().lower().replace("_", "-").replace(" ", "-")
    for suffix in _DEPLOYMENT_SUFFIXES:
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    return s


# =============================================================================
# Prompt lookup
# =============================================================================
def _query_prompt(sb, agent: str, version: str | None = None) -> dict | None:
    """Query prompt_db for an active row matching agent (+ optional version).

    Returns the single row or None. Never raises — supabase errors surface
    as None so the caller can fall through to the next candidate.
    """
    if not agent:
        return None
    try:
        q = (
            sb.table("prompt_db")
            .select("agent,version,model,prompt_text,parameters")
            .eq("agent", agent)
            .eq("is_active", True)
        )
        if version:
            q = q.eq("version", version)
        resp = q.limit(1).execute()
        rows = resp.data or []
        return rows[0] if rows else None
    except Exception:  # noqa: BLE001
        return None


def load_sa3_prompt(
    sb,
    *,
    source: str | None,
    family: str | None,
    version_hint: str | None = None,
    default_version: str | None = None,
) -> dict:
    """Resolve the SA-3 prompt for a (source, family) combo.

    Args:
        sb:              supabase client (public schema — prompts live there)
        source:          issue.source, e.g. "trivy-os", "trivy-image", "checkov"
        family:          classified family, e.g. "os_vulnerability"
        version_hint:    optional exact version to fetch on the SPECIALIZED
                         prompts (usually left None so the active row wins)
        default_version: version to fetch on the generic fallback
                         (planner_demo uses "v1.4", agent_v2 uses "v2.0")

    Returns:
        The prompt row dict {agent, version, model, prompt_text, parameters}.

    Raises:
        RuntimeError if even the generic fallback can't be loaded.
    """
    src = _slug(source)
    fam = (family or "").strip().lower()

    candidates: list[tuple[str, str | None]] = []

    if src and fam:
        candidates.append((f"sub-agent-3-{src}-{fam}", version_hint))
    if src:
        candidates.append((f"sub-agent-3-{src}", version_hint))
    if fam:
        candidates.append((f"sub-agent-3-{fam}", version_hint))
    # Generic fallback — never break current behavior
    candidates.append(("sub-agent-3", default_version))

    for agent_name, version in candidates:
        row = _query_prompt(sb, agent_name, version)
        if row:
            return row

    raise RuntimeError(
        f"SA-3 prompt router: no prompt found for source={source!r} family={family!r}. "
        "Tried "
        + ", ".join(f"{a}@{v or 'active'}" for a, v in candidates)
        + ". Ensure at least the generic sub-agent-3 prompt is seeded."
    )


# =============================================================================
# Convenience: which candidate hit?
# =============================================================================
def describe_selected_prompt(prompt_row: dict, source: str | None, family: str | None) -> str:
    """Human-readable summary for trace events — tells operators which
    prompt actually got selected (generic fallback vs specialized)."""
    agent = prompt_row.get("agent", "?")
    version = prompt_row.get("version", "?")
    src = _slug(source)
    fam = (family or "").strip().lower()

    if agent == f"sub-agent-3-{src}-{fam}":
        specificity = "specialized (source+family)"
    elif agent == f"sub-agent-3-{src}":
        specificity = "source-specific"
    elif agent == f"sub-agent-3-{fam}":
        specificity = "family-specific"
    elif agent == "sub-agent-3":
        specificity = "generic fallback"
    else:
        specificity = "custom"

    return f"{agent}@{version} ({specificity})"


# =============================================================================
# Introspection helper — useful for /admin endpoints later
# =============================================================================
def list_available_sa3_prompts(sb) -> list[dict]:
    """Return every SA-3 flavored prompt currently active. Handy for a future
    admin UI that shows which specialized prompts are wired."""
    try:
        resp = (
            sb.table("prompt_db")
            .select("agent,version,model,is_active")
            .like("agent", "sub-agent-3%")
            .eq("is_active", True)
            .order("agent")
            .execute()
        )
        return resp.data or []
    except Exception:  # noqa: BLE001
        return []
