"""Connector dispatcher.

Sub-Agent 1 calls `fetch_raw_rows()` to get raw scanner rows. The dispatcher
picks the right implementation based on `metadata.connector_type` in the
connection_registry row.

Currently registered:
  - "osv_api"        → public OSV.dev vulnerability database
  - "tenable_api"    → real local Nessus instance over HTTPS
  - "user_endpoint"  → generic user-supplied HTTP endpoint (any tool)
  - "file_upload"    → user-uploaded scanner export (JSON/JSONL/CSV/SARIF)
"""

from . import file_upload, osv_api, tenable_api, user_endpoint


def fetch_raw_rows(
    tool: str,
    registry_entry: dict,
    last_fetched_at: str | None,
    *,
    run_id: str | None = None,
) -> list[dict]:
    """Dispatch to the right connector based on metadata.connector_type.

    `run_id` is forwarded to the generic connectors (user_endpoint, file_upload)
    so they can bill LLM-assisted response-path inference to the active run.
    Purpose-built connectors (osv_api, tenable_api) don't need it.
    """
    metadata = registry_entry.get("metadata") or {}
    connector_type = metadata.get("connector_type")

    if connector_type == "osv_api":
        return osv_api.fetch(registry_entry, last_fetched_at)
    if connector_type == "tenable_api":
        return tenable_api.fetch(registry_entry, last_fetched_at)
    if connector_type == "user_endpoint":
        return user_endpoint.fetch(registry_entry, last_fetched_at, run_id=run_id)
    if connector_type == "file_upload":
        return file_upload.fetch(registry_entry, last_fetched_at, run_id=run_id)
    raise ValueError(
        f"unknown or missing connector_type {connector_type!r} for tool {tool!r}. "
        "Update connection_registry.metadata.connector_type."
    )
