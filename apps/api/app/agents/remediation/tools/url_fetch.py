"""URL fetch tool for the agentic Sub-Agent 3.

Given a URL (usually from web_search's Tier-1/2 results), download the page
and extract clean readable content. Preserves headings + code blocks so
Sub-Agent 3 can quote remediation steps verbatim in the package.

Returns compact result the LLM can use directly:
  {
    "url": "...",
    "final_url": "...",       # after redirects
    "title": "...",
    "text": "..."             # cleaned markdown/text (trafilatura output)
    "content_length": 4200,   # chars of cleaned text
    "status_code": 200,
    "elapsed_ms": 850,
  }

Guards:
  - 15s hard timeout on the HTTP call
  - Max 200 KB of raw HTML processed (protects against giant pages)
  - Only text/html + text/markdown content-types accepted
  - User-Agent identifies us as a research bot (robots-friendly)
  - Budget-aware: refuses if budget cap already hit
"""

from __future__ import annotations

import time
from typing import Any

import httpx

try:
    import trafilatura
except ImportError:  # pragma: no cover
    trafilatura = None  # type: ignore[assignment]

from .budget import AgentBudget


# Cap raw HTML we send through the extractor. Way more than any real doc page
# needs and keeps us out of pathological cases (huge homepages, error dumps).
_MAX_HTML_BYTES = 200 * 1024

# Identifies us honestly + gives site operators a way to reach us if we're
# being noisy. Bots that identify themselves get through robots.txt more often.
_USER_AGENT = (
    "SisyfixAgentic/0.1 (+security-remediation-research; contact via HTTP headers)"
)


def fetch_url(
    url: str,
    budget: AgentBudget,
    *,
    timeout_s: float = 15.0,
    max_chars_returned: int = 8000,
    run_id: str | None = None,
    emit_fn=None,  # trace emitter (real=emit_trace, demo=emit_trace_demo)
) -> dict[str, Any]:
    """Fetch a URL and return extracted clean text.

    Raises RuntimeError on:
      - trafilatura not installed
      - budget cap reached
      - non-text content type
      - HTTP errors (4xx / 5xx / timeouts)

    `max_chars_returned` caps the text sent back to the agent — Sub-Agent 3
    doesn't need 30-page RFCs verbatim, just the remediation-relevant portion.
    Truncated with a marker so the LLM knows content was cut.
    """
    if trafilatura is None:
        raise RuntimeError("trafilatura is not installed. Run: uv sync")

    allowed, reason = budget.can_call()
    if not allowed:
        raise RuntimeError(f"url_fetch denied: {reason}")

    if emit_fn and run_id:
        emit_fn(
            run_id, "sub-agent-3", "MESSAGE",
            f"📄 Fetching URL: {url[:150]}"
            f" (call {budget.call_count + 1}/{budget.max_calls})",
        )

    start = time.time()
    try:
        with httpx.Client(
            headers={"User-Agent": _USER_AGENT, "Accept": "text/html, text/*"},
            follow_redirects=True,
            timeout=timeout_s,
        ) as client:
            resp = client.get(url)
    except httpx.HTTPError as e:
        if emit_fn and run_id:
            emit_fn(
                run_id, "sub-agent-3", "ERROR",
                f"Fetch failed for {url[:100]}: {type(e).__name__}: {str(e)[:150]}",
            )
        # Still record the call — a failed fetch costs bandwidth + our attention
        budget.record_call("url_fetch")
        raise RuntimeError(f"HTTP fetch failed: {type(e).__name__}: {str(e)[:150]}") from e

    budget.record_call("url_fetch")
    elapsed_ms = int((time.time() - start) * 1000)

    if resp.status_code >= 400:
        if emit_fn and run_id:
            emit_fn(
                run_id, "sub-agent-3", "ERROR",
                f"HTTP {resp.status_code} from {url[:100]}",
            )
        raise RuntimeError(f"HTTP {resp.status_code} from {url}")

    # Content-type check — skip non-text (PDF, images, JSON APIs, etc.)
    ctype = (resp.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if not ctype.startswith(("text/html", "text/plain", "text/markdown", "application/xhtml")):
        raise RuntimeError(f"Non-text content-type: {ctype}")

    # Cap raw HTML size — protects trafilatura from OOM on giant pages
    raw = resp.content[:_MAX_HTML_BYTES]

    # Extract clean text/markdown. output='markdown' preserves code blocks.
    extracted = trafilatura.extract(
        raw,
        output_format="markdown",
        include_comments=False,
        include_tables=True,
        favor_precision=True,
    ) or ""

    # Title extraction — trafilatura's metadata pass
    title = ""
    try:
        meta = trafilatura.extract_metadata(raw)
        if meta and getattr(meta, "title", None):
            title = meta.title
    except Exception:  # noqa: BLE001 — metadata is best-effort
        pass

    # Truncate to what Sub-Agent 3 can actually consume in context
    truncated = False
    if len(extracted) > max_chars_returned:
        extracted = extracted[:max_chars_returned] + "\n\n[... truncated for LLM context budget ...]"
        truncated = True

    if emit_fn and run_id:
        emit_fn(
            run_id, "sub-agent-3", "MESSAGE",
            f"Fetched {len(extracted)} chars in {elapsed_ms}ms"
            + (" (truncated)" if truncated else "")
            + f" — {title[:80]}" if title else "",
        )

    return {
        "url": url,
        "final_url": str(resp.url),
        "title": title,
        "text": extracted,
        "content_length": len(extracted),
        "truncated": truncated,
        "status_code": resp.status_code,
        "content_type": ctype,
        "elapsed_ms": elapsed_ms,
    }
