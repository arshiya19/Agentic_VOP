"""Generic file-upload connector.

Used when a tool can't be reached over HTTP (air-gapped scans, manual
exports, etc.) but the user has uploaded a scanner-output file via the
Integrations page. The file is stored in the Supabase `scanner_uploads`
bucket; we download and parse it here, then hand raw rows to Sub-Agent 1.

Configuration (all under `connection_registry.metadata`):

  file_pointer    : path inside the `scanner_uploads` bucket — set by
                    POST /admin/scanners/{tool}/upload, never by the user
                    directly.
  file_format     : "json" | "jsonl" | "csv" | "sarif" — sniffed at upload
                    time from the filename / content; the user can override
                    if the sniff is wrong.
  file_filename   : original filename (for display in the UI).
  response_path   : same as user_endpoint — only consulted for "json".

Supported formats:
  - **JSON**  : single payload, shape resolved via shared shape utilities
                (explicit path → common-key auto-detect → LLM inference).
  - **JSONL** : one JSON object per line. Each line is a raw row.
  - **CSV**   : header row + data rows. Each row is a dict keyed by header.
  - **SARIF** : industry-standard schema. Findings live under
                `runs[].results[]`. We flatten across runs and stamp each
                result with its enclosing rule + tool name so Sub-Agent 1
                can build asset_identity / package without re-joining.

Re-fetch semantics: re-running a scan re-reads the same uploaded file. To
replace the data, the user re-uploads via the Integrations modal, which
overwrites `file_pointer`.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from ...db import supabase_admin
from ._shape_utils import (
    infer_response_path,
    persist_response_path,
    try_simple_extract,
)


SCANNER_BUCKET = "scanner_uploads"


# ----------------------------------------------------------------------------
# Format-specific parsers
# ----------------------------------------------------------------------------


def _parse_jsonl(content: bytes) -> list[dict]:
    rows: list[dict] = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _parse_csv(content: bytes) -> list[dict]:
    text = content.decode("utf-8-sig", errors="replace")  # strip BOM if present
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def _parse_sarif(content: bytes) -> list[dict]:
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


def _parse_json(
    content: bytes,
    response_path: str | None,
    registry_entry: dict,
    run_id: str | None,
) -> list[dict]:
    payload: Any = json.loads(content.decode("utf-8", errors="replace"))

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


# ----------------------------------------------------------------------------
# Format sniffing
# ----------------------------------------------------------------------------


def sniff_format(filename: str, content: bytes) -> str:
    """Pick a format based on filename + light content inspection.

    Order of checks:
      1. Filename extension (cheap, usually right).
      2. SARIF detection — if it parses as JSON with a top-level "runs" key,
         it's almost certainly SARIF even if the extension is .json.
      3. JSONL detection — multiple lines, each parsable as JSON.
      4. Fallback to "json".
    """
    name = (filename or "").lower()
    if name.endswith(".sarif"):
        return "sarif"
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "jsonl"
    if name.endswith(".csv"):
        return "csv"

    # JSON-ish — sniff for SARIF.
    if name.endswith(".json") or not name:
        try:
            head = content[:8192].decode("utf-8", errors="replace").lstrip()
            if head.startswith("{") and '"runs"' in content[:2048].decode("utf-8", "replace"):
                return "sarif"
        except Exception:  # nosec B110 — intentional: sniffing is best-effort, fall through to "json"  # noqa: S110
            pass
        return "json"

    return "json"  # last resort — let the JSON parser try


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------


def fetch(
    registry_entry: dict,
    last_fetched_at: str | None = None,  # noqa: ARG001
    *,
    run_id: str | None = None,
) -> list[dict]:
    """Download the uploaded file from Supabase Storage, parse it, and return
    raw rows for Sub-Agent 1.
    """
    metadata = registry_entry.get("metadata") or {}
    file_pointer = metadata.get("file_pointer")
    if not file_pointer:
        raise ValueError(
            "file_upload connector: no file_pointer in metadata. "
            "Upload a file via POST /admin/scanners/{tool}/upload first."
        )

    sb = supabase_admin()
    content: bytes = sb.storage.from_(SCANNER_BUCKET).download(file_pointer)
    if not content:
        raise ValueError(
            f"file_upload connector: download of '{file_pointer}' returned empty content."
        )

    file_format = (metadata.get("file_format") or "json").lower()
    response_path = metadata.get("response_path")

    if file_format == "jsonl":
        return _parse_jsonl(content)
    if file_format == "csv":
        return _parse_csv(content)
    if file_format == "sarif":
        return _parse_sarif(content)
    return _parse_json(content, response_path, registry_entry, run_id)
