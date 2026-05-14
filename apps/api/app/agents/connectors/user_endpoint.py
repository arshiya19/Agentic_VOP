"""Generic user-supplied-endpoint connector.

Used when a tool has no purpose-built connector but the user has provided an
HTTP endpoint that returns scanner findings. The shape of the response is
intentionally permissive — Sub-Agent 1's LLM normalizes whatever comes back,
so this connector just has to deliver a `list[dict]` of raw rows.

Configuration (all under `connection_registry.metadata`):

  http_method        : "GET" (default) | "POST"
  headers            : dict[str, str] — sent verbatim; put auth here, e.g.
                          {"Authorization": "Bearer <token>"}
  body               : dict | list — JSON body for POST (ignored for GET)
  response_path      : dotted path to the array inside the response, e.g.
                          "data.findings". Optional — see "Locating the array".

Locating the array uses the shared three-tier fallback in `_shape_utils`:
explicit path → common-key auto-detect → LLM inference (cached).

Watermark behavior: not enforced here — the user's endpoint typically can't
filter server-side without bespoke logic. Sub-Agent 1 still records its
own watermark for replay accounting; older rows get re-normalized but that's
cheap and idempotent at the issues layer.
"""

from __future__ import annotations

import httpx

from ._shape_utils import (
    infer_response_path,
    persist_response_path,
    try_simple_extract,
)


def fetch(
    registry_entry: dict,
    last_fetched_at: str | None = None,  # noqa: ARG001
    *,
    run_id: str | None = None,
) -> list[dict]:
    """Hit the user-defined endpoint and return raw rows for Sub-Agent 1."""
    endpoint = registry_entry.get("endpoint")
    if not endpoint:
        raise ValueError("user_endpoint connector: registry row has no endpoint")

    metadata = registry_entry.get("metadata") or {}
    method = (metadata.get("http_method") or "GET").upper()
    headers = metadata.get("headers") or {}
    body = metadata.get("body")
    response_path = metadata.get("response_path")
    timeout_sec = int(registry_entry.get("timeout_sec") or 60)

    with httpx.Client(timeout=timeout_sec) as client:
        if method == "POST":
            resp = client.post(endpoint, headers=headers, json=body)
        else:
            resp = client.get(endpoint, headers=headers)
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError as e:
            raise ValueError(
                f"user_endpoint connector: response from {endpoint} was not valid JSON"
            ) from e

    return _extract_with_fallbacks(payload, response_path, registry_entry, run_id)


def _extract_with_fallbacks(
    payload,
    response_path: str | None,
    registry_entry: dict,
    run_id: str | None,
) -> list[dict]:
    """Tier 1+2+3 fallback chain shared with the file_upload connector."""
    rows = try_simple_extract(payload, response_path)

    if rows is None and run_id and not response_path:
        inferred = infer_response_path(payload, run_id)
        if inferred is not None:
            rows = try_simple_extract(payload, inferred or None)
            if rows is not None:
                tool = registry_entry.get("tool")
                if tool:
                    persist_response_path(tool, inferred)

    if rows is None:
        rows = [payload] if isinstance(payload, dict) else []

    return rows
