"""Tavily web-search tool for the agentic Sub-Agent 3.

Wraps the Tavily Python SDK in:
  - a per-run budget tracker (call count + estimated cost)
  - a domain-authority scorer (prioritises AWS/CIS/NVD/CISA over blogs)
  - an emit_fn hook so the Agents page can show live search progress

Returns a compact, LLM-friendly result shape:
  {
    "query": "the original query",
    "results": [
      {"url": "...", "title": "...", "snippet": "...", "authority_tier": 1, "published_date": "..."},
      ...
    ],
    "raw_answer": "Tavily's synthesized answer (optional, when include_answer=True)",
  }

Cost model:
  Tavily free tier: 1000 searches/month, no per-search cost.
  Tavily paid tier: ~$0.01 per search (basic), ~$0.05 (advanced).
  We estimate ADVANCED at $0.05 per call for budget math — pessimistic on
  free tier (no real charge but the counter still fires so we exercise the
  budget-cap logic during dev).
"""

from __future__ import annotations

import time
from typing import Any

try:
    from tavily import TavilyClient
except ImportError:  # pragma: no cover — package installed at runtime
    TavilyClient = None  # type: ignore[assignment]

from ....config import settings
from .budget import AgentBudget


# =============================================================================
# Domain authority tiers — used to rank search results before the agent reads them.
# Lower tier = more authoritative.
# =============================================================================
_TIER_1_DOMAINS = {
    # Cloud provider primary security docs
    "docs.aws.amazon.com", "aws.amazon.com", "docs.microsoft.com",
    "learn.microsoft.com", "cloud.google.com", "docs.oracle.com",
    # Standards bodies + governments
    "cisecurity.org", "cis-cat.readthedocs.io",
    "nvd.nist.gov", "nist.gov",
    "cisa.gov", "www.cisa.gov",
    "csrc.nist.gov",
    # MITRE
    "cwe.mitre.org", "capec.mitre.org", "attack.mitre.org",
}
_TIER_2_DOMAINS = {
    # OWASP + community security orgs
    "owasp.org", "cheatsheetseries.owasp.org",
    # Vendor security advisories
    "kubernetes.io", "docs.kubernetes.io",
    "hashicorp.com", "developer.hashicorp.com",
    "terraform.io",
    # CVE databases
    "cve.mitre.org", "vulners.com",
    # Official security research
    "cert.org", "us-cert.gov",
    "portswigger.net",  # Burp / PortSwigger research
}
_TIER_3_DOMAINS = {
    # Reputable security vendors' research pages
    "snyk.io", "checkov.io", "trivy.dev", "aquasec.com",
    "wiz.io", "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "crowdstrike.com", "rapid7.com",
    "sonarsource.com", "semgrep.dev",
    # GitHub advisory database
    "github.com", "docs.github.com",
}


def _score_domain(url: str) -> int:
    """Return an authority tier for a URL (1 = most authoritative, 4 = blogs/other)."""
    url_lower = url.lower()
    # Match by containment so subdomains work (e.g. docs.aws.amazon.com/... hits aws.amazon.com).
    for domain in _TIER_1_DOMAINS:
        if domain in url_lower:
            return 1
    for domain in _TIER_2_DOMAINS:
        if domain in url_lower:
            return 2
    for domain in _TIER_3_DOMAINS:
        if domain in url_lower:
            return 3
    return 4


# =============================================================================
# Public search function — what the agent calls.
# =============================================================================
def web_search(
    query: str,
    budget: AgentBudget,
    *,
    max_results: int = 6,
    search_depth: str = "advanced",  # 'basic' cheaper; 'advanced' better for security docs
    include_answer: bool = False,
    include_domains: list[str] | None = None,
    exclude_domains: list[str] | None = None,
    run_id: str | None = None,
    emit_fn=None,  # optional trace emitter (route: real=emit_trace, demo=emit_trace_demo)
) -> dict[str, Any]:
    """Run one Tavily search, respecting the per-run budget.

    Returns a dict with 'results' (list) + 'query' + optional 'raw_answer'.
    Each result is sorted by authority tier (Tier 1 first).

    Raises RuntimeError if:
      - Tavily is not installed
      - TAVILY_API_KEY is not configured
      - Budget cap has been reached (caller should trigger fallback)
    """
    if TavilyClient is None:
        raise RuntimeError("tavily-python is not installed. Run: pip install tavily-python")
    if not settings.tavily_api_key:
        raise RuntimeError("TAVILY_API_KEY is not set in .env")

    allowed, reason = budget.can_call()
    if not allowed:
        raise RuntimeError(f"web_search denied: {reason}")

    if emit_fn and run_id:
        emit_fn(
            run_id, "sub-agent-3", "MESSAGE",
            f"🔍 Searching web: {query[:120]}"
            f" (call {budget.call_count + 1}/{budget.max_calls})",
        )

    start = time.time()
    client = TavilyClient(api_key=settings.tavily_api_key)
    try:
        raw = client.search(
            query=query,
            search_depth=search_depth,
            max_results=max_results,
            include_answer=include_answer,
            include_domains=include_domains or [],
            exclude_domains=exclude_domains or [],
        )
    except Exception as e:  # noqa: BLE001
        if emit_fn and run_id:
            emit_fn(
                run_id, "sub-agent-3", "ERROR",
                f"Search failed: {type(e).__name__}: {str(e)[:200]}",
            )
        raise

    budget.record_call("web_search")
    elapsed_ms = int((time.time() - start) * 1000)

    # Normalise Tavily's result shape + score + sort by tier
    results = []
    for r in raw.get("results", []) or []:
        url = r.get("url", "")
        tier = _score_domain(url)
        results.append({
            "url": url,
            "title": r.get("title", ""),
            "snippet": r.get("content", "")[:600],  # keep the LLM context tight
            "authority_tier": tier,
            "published_date": r.get("published_date"),
            "score": r.get("score"),  # Tavily's relevance score
        })
    results.sort(key=lambda r: (r["authority_tier"], -1 * (r.get("score") or 0)))

    if emit_fn and run_id:
        top_domains = sorted({r["url"].split("/")[2] for r in results[:3] if "/" in r["url"]})
        emit_fn(
            run_id, "sub-agent-3", "MESSAGE",
            f"Search returned {len(results)} result(s) in {elapsed_ms}ms · "
            f"top: {', '.join(top_domains)[:150]}",
        )

    return {
        "query": query,
        "results": results,
        "raw_answer": raw.get("answer") if include_answer else None,
        "elapsed_ms": elapsed_ms,
    }
