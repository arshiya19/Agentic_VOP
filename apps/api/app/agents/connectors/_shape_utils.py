"""Shared shape-detection helpers used by `user_endpoint` and `file_upload`.

Both connectors face the same problem: a payload of arbitrary shape arrives,
and we need to locate the array of finding dicts inside it. The strategy is:

  1. Try `_try_simple_extract` with an explicit `response_path` (if set) or
     a small set of common top-level keys (vulnerabilities, findings, etc.).
  2. If that returns None, fall back to `_infer_response_path` — a tiny LLM
     call that reads a key-only JSON skeleton and returns the dotted path.
  3. Persist the inferred path back into connection_registry.metadata so
     subsequent runs skip the LLM call entirely.

Also houses `parse_sarif` — the canonical SARIF flattener shared by both
`file_upload` (uploaded .sarif files) and `user_endpoint` (ZIP-extracted
.sarif files).
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field

from ...db import supabase_admin
from ..llm import invoke_structured_with_retry


_COMMON_LIST_KEYS = (
    "vulnerabilities",
    "findings",
    "results",
    "items",
    "data",
    "records",
)


def _resolve_path(payload: Any, path: str) -> Any:
    """Walk a dotted path (e.g. 'data.findings' or 'runs.0.results') into a
    nested dict / list. Returns None if any segment can't be resolved.
    """
    node: Any = payload
    for segment in path.split("."):
        if isinstance(node, dict) and segment in node:
            node = node[segment]
        elif isinstance(node, list) and segment.isdigit():
            idx = int(segment)
            if 0 <= idx < len(node):
                node = node[idx]
            else:
                return None
        else:
            return None
    return node


def try_simple_extract(payload: Any, response_path: str | None) -> list[dict] | None:
    """Return a list of finding dicts if we can confidently locate one.

    Returns None when neither an explicit `response_path` nor a common-key
    auto-detect succeeds — the caller then falls back to LLM inference.
    """
    if response_path:
        node = _resolve_path(payload, response_path)
        if isinstance(node, list):
            return [r for r in node if isinstance(r, dict)]
        if isinstance(node, dict):
            return [node]
        return None

    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]

    if isinstance(payload, dict):
        for key in _COMMON_LIST_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]

    return None


# ----------------------------------------------------------------------------
# LLM-assisted path inference
# ----------------------------------------------------------------------------


class _ResponsePathInference(BaseModel):
    """Tool-call schema for the path-inference LLM call."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        ...,
        description=(
            "Dotted path to the array of finding dicts, e.g. 'data.findings'. "
            "Empty string if the payload itself is the array."
        ),
    )
    explanation: str = Field(
        ...,
        min_length=1,
        max_length=300,
        description="One-sentence reasoning for the chosen path.",
    )


_PATH_INFERENCE_SYSTEM_PROMPT = """You analyze JSON shapes from security scanners
and identify where the array of vulnerability findings lives inside the payload.

You will receive a JSON skeleton — keys preserved, values replaced with type
placeholders like "<str>", "<num>", and arrays shown as `[<sample>, "...len=N"]`.

Return:
  - path: a dotted path that, when applied to the original payload, yields the
    array of finding dicts (e.g. "data.findings", "vulnerabilities",
    "runs.0.results"). Use the empty string "" when the payload itself is the
    array.
  - explanation: one short sentence on why you picked that path.

Examples:
  Skeleton: [{"id": "<str>"}, "...len=10"]
    → path: ""
  Skeleton: {"vulnerabilities": [{"cve": "<str>"}, "...len=5"], "total": "<num>"}
    → path: "vulnerabilities"
  Skeleton: {"data": {"findings": [{"id": "<str>"}, "...len=20"]}}
    → path: "data.findings"
  Skeleton: {"version": "<str>", "runs": [{"results": [{"ruleId": "<str>"}, "...len=8"]}]}
    → path: "runs.0.results"
"""


def json_skeleton(value: Any, max_depth: int = 5, max_keys_per_dict: int = 40) -> Any:
    """Reduce a JSON payload to a key+type skeleton.

    Drops actual values so we don't ship sensitive data to the LLM, and caps
    depth / key count so massive payloads still produce a compact prompt.
    """
    if max_depth <= 0:
        return "..."
    if isinstance(value, dict):
        keys = list(value.keys())[:max_keys_per_dict]
        return {k: json_skeleton(value[k], max_depth - 1, max_keys_per_dict) for k in keys}
    if isinstance(value, list):
        if not value:
            return []
        sample = json_skeleton(value[0], max_depth - 1, max_keys_per_dict)
        return [sample, f"...len={len(value)}"]
    if isinstance(value, bool):
        return "<bool>"
    if isinstance(value, (int, float)):
        return "<num>"
    if isinstance(value, str):
        return "<str>"
    if value is None:
        return None
    return f"<{type(value).__name__}>"


def infer_response_path(payload: Any, run_id: str) -> str | None:
    """Ask the LLM where the findings array lives. Returns the dotted path
    (or empty string for top-level arrays). Returns None if the call fails.

    Always uses gpt-4o-mini — this is a small structural task and OpenAI is
    the always-available provider regardless of which model is configured
    for Sub-Agent 1.
    """
    skeleton = json_skeleton(payload)
    try:
        result: _ResponsePathInference = invoke_structured_with_retry(
            run_id=run_id,
            agent="sub-agent-1",
            schema=_ResponsePathInference,
            messages=[
                SystemMessage(content=_PATH_INFERENCE_SYSTEM_PROMPT),
                HumanMessage(content=f"JSON skeleton:\n{skeleton}"),
            ],
            attempts=[
                (0.0, "gpt-4o-mini", 400),
                (0.3, "gpt-4o-mini", 600),
            ],
        )
    except Exception:
        return None

    return result.path if result is not None else None


def persist_response_path(tool: str, path: str) -> None:
    """Cache the inferred path back into connection_registry.metadata so the
    next fetch skips the LLM inference step entirely.
    """
    try:
        sb = supabase_admin()
        existing = (
            sb.table("connection_registry")
            .select("metadata")
            .eq("tool", tool)
            .single()
            .execute()
            .data
        )
        if not existing:
            return
        new_metadata = {**(existing.get("metadata") or {}), "response_path": path}
        sb.table("connection_registry").update({"metadata": new_metadata}).eq(
            "tool", tool
        ).execute()
    except Exception:
        # Caching is best-effort; a failure here just means we re-infer next time.
        return



# ----------------------------------------------------------------------------
# SARIF flattener — shared by file_upload and user_endpoint (ZIP extraction)
# ----------------------------------------------------------------------------


def parse_sarif(content: bytes) -> list[dict]:
    """Flatten SARIF: emit one row per `runs[].results[]` entry, decorated
    with the tool name + rule metadata so Sub-Agent 1 has full context.
    """
    sarif = json.loads(content.decode("utf-8", errors="replace"))
    rows: list[dict] = []
    for run in sarif.get("runs", []) or []:
        tool_block = (run.get("tool") or {}).get("driver") or {}
        tool_name = tool_block.get("name")
        rules_by_id = {r.get("id"): r for r in tool_block.get("rules", []) if r.get("id")}

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId")
            rule = rules_by_id.get(rule_id) or {}
            rows.append(
                {
                    "sarif_tool": tool_name,
                    "sarif_rule_id": rule_id,
                    "sarif_rule_name": rule.get("name"),
                    "sarif_rule_short_description": (rule.get("shortDescription") or {}).get(
                        "text"
                    ),
                    "sarif_rule_full_description": (rule.get("fullDescription") or {}).get("text"),
                    "sarif_rule_help_uri": rule.get("helpUri"),
                    "sarif_level": result.get("level"),
                    "sarif_message": (result.get("message") or {}).get("text"),
                    "sarif_locations": result.get("locations", []),
                    "sarif_properties": result.get("properties", {}),
                    "sarif_partial_fingerprints": result.get("partialFingerprints", {}),
                }
            )
    return rows
