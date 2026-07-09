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
_USER_AGENT = "SisyfixAgentic/0.1 (+security-remediation-research; contact via HTTP headers)"

# Content-quality thresholds. Pages under these bars can't sustain a detailed
# remediation package — the LLM will happily write shallow steps unless we
# push back explicitly. See _quality_warning below.
_QUALITY_EMPTY_THRESHOLD = 100  # essentially unusable — JS-rendered SPA / error page
_QUALITY_THIN_THRESHOLD = 400  # extractable but sparse — should not be sole source


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
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"📄 Fetching URL: {url[:150]} (call {budget.call_count + 1}/{budget.max_calls})",
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
                run_id,
                "sub-agent-3",
                "ERROR",
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
                run_id,
                "sub-agent-3",
                "ERROR",
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
    extracted = (
        trafilatura.extract(
            raw,
            output_format="markdown",
            include_comments=False,
            include_tables=True,
            favor_precision=True,
        )
        or ""
    )

    # Title extraction — trafilatura's metadata pass
    title = ""
    try:
        meta = trafilatura.extract_metadata(raw)
        if meta and getattr(meta, "title", None):
            title = meta.title
    except Exception:  # noqa: BLE001, S110 — metadata is best-effort
        pass

    # Truncate to what Sub-Agent 3 can actually consume in context
    truncated = False
    if len(extracted) > max_chars_returned:
        extracted = (
            extracted[:max_chars_returned] + "\n\n[... truncated for LLM context budget ...]"
        )
        truncated = True

    # Assess extraction quality — pages under our thresholds get an explicit
    # warning the agent tool wrapper will surface to the LLM so it knows to
    # go find a better source instead of silently synthesizing on nothing.
    quality_warning = _quality_warning(len(extracted), url)

    if emit_fn and run_id:
        base = f"Fetched {len(extracted)} chars in {elapsed_ms}ms" + (
            " (truncated)" if truncated else ""
        )
        if quality_warning:
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"⚠ {quality_warning['level']} CONTENT — {base} — {title[:60]}"
                if title
                else f"⚠ {quality_warning['level']} — {base}",
            )
        elif title:
            emit_fn(run_id, "sub-agent-3", "MESSAGE", f"{base} — {title[:80]}")
        else:
            emit_fn(run_id, "sub-agent-3", "MESSAGE", base)

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
        "quality_warning": quality_warning,  # None on healthy extractions
    }


def _quality_warning(n_chars: int, url: str) -> dict | None:
    """Classify extraction as EMPTY / THIN / OK and produce a directive the
    tool wrapper can surface verbatim to the LLM.

    The LLM's default behavior when a fetch returns little text is to just
    keep going and synthesize with whatever it has. That's how we end up with
    2-step remediation packages. This warning is the pushback signal.
    """
    if n_chars < _QUALITY_EMPTY_THRESHOLD:
        return {
            "level": "EMPTY",
            "chars": n_chars,
            "url": url,
            "directive": (
                f"URL returned only {n_chars} chars of readable content. "
                f"This page is almost certainly a JavaScript-rendered SPA that "
                f"our headless fetcher cannot read (common on modern vendor "
                f"docs). This source is UNUSABLE and MUST NOT be cited. "
                f"Call web_search NOW for an alternative authoritative source "
                f"(prefer AWS/Azure/GCP official docs, CIS Benchmark PDFs, "
                f"MITRE, NVD, or vendor CLI reference pages) and url_fetch that."
            ),
        }
    if n_chars < _QUALITY_THIN_THRESHOLD:
        return {
            "level": "THIN",
            "chars": n_chars,
            "url": url,
            "directive": (
                f"URL returned only {n_chars} chars — insufficient to derive "
                f"detailed enterprise-grade remediation from. This source is "
                f"acceptable as a SECONDARY citation but NOT as your primary "
                f"reference. Continue researching: call web_search for a more "
                f"comprehensive authoritative doc and url_fetch that as well."
            ),
        }
    return None
