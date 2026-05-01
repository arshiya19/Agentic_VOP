"""Connector dispatcher.

Sub-Agent 1 calls `fetch_raw_rows()` to get raw scanner rows. The dispatcher
picks the right implementation based on `metadata.connector_type` in the
connection_registry row.

Currently registered:
  - "osv_api"      → public OSV.dev vulnerability database
  - "tenable_api"  → real local Nessus instance over HTTPS
"""

from . import osv_api, tenable_api


def fetch_raw_rows(
    tool: str,
    registry_entry: dict,
    last_fetched_at: str | None,
) -> list[dict]:
    """Dispatch to the right connector based on metadata.connector_type."""
    metadata = registry_entry.get("metadata") or {}
    connector_type = metadata.get("connector_type")

    if connector_type == "osv_api":
        return osv_api.fetch(registry_entry, last_fetched_at)
    if connector_type == "tenable_api":
        return tenable_api.fetch(registry_entry, last_fetched_at)
    raise ValueError(
        f"unknown or missing connector_type {connector_type!r} for tool {tool!r}. "
        "Update connection_registry.metadata.connector_type."
    )
