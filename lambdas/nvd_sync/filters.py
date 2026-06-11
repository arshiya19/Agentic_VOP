"""CVE filtering utilities for the NVD sync pipeline.

This module provides functions to filter NVD 2.0 CVE items based on
checkpoint timestamps, enabling incremental sync by processing only
items modified after the last successful sync.
"""

from __future__ import annotations


def filter_cves_by_checkpoint(
    cve_items: list[dict], checkpoint_timestamp: str | None
) -> list[dict]:
    """Filter CVE items to include only those modified after the checkpoint.

    Compares each item's ``cve.lastModified`` field against the checkpoint
    timestamp string.  ISO 8601 timestamps sort lexicographically, so a
    simple string comparison (``>``) is sufficient for correctness.

    Args:
        cve_items: List of NVD 2.0 CVE JSON objects from the feed.
            Each item is expected to have the structure:
            ``{"cve": {"id": "CVE-...", "lastModified": "2024-01-16T12:00:00.000", ...}}``
        checkpoint_timestamp: ISO 8601 timestamp of the last successful sync,
            or ``None`` for the first sync (returns all items).

    Returns:
        List of CVE items whose ``lastModified`` is strictly greater than
        *checkpoint_timestamp*.  Items missing the ``lastModified`` field
        are skipped (excluded from the result).
    """
    # On first sync (no checkpoint), return all items that have a valid
    # lastModified field.
    if checkpoint_timestamp is None:
        return [item for item in cve_items if _get_last_modified(item) is not None]

    return [
        item
        for item in cve_items
        if _is_newer_than_checkpoint(item, checkpoint_timestamp)
    ]


def _get_last_modified(item: dict) -> str | None:
    """Extract the lastModified timestamp from an NVD 2.0 CVE item.

    Args:
        item: A single NVD 2.0 CVE JSON object.

    Returns:
        The ``lastModified`` string if present, or ``None`` if the field
        is missing or the item structure is invalid.
    """
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    last_modified = cve.get("lastModified")
    if not isinstance(last_modified, str):
        return None
    return last_modified


def _is_newer_than_checkpoint(item: dict, checkpoint_timestamp: str) -> bool:
    """Check whether a CVE item was modified after the checkpoint.

    Args:
        item: A single NVD 2.0 CVE JSON object.
        checkpoint_timestamp: ISO 8601 checkpoint timestamp string.

    Returns:
        ``True`` if the item's ``lastModified`` is strictly greater than
        *checkpoint_timestamp*; ``False`` otherwise (including when
        ``lastModified`` is missing).
    """
    last_modified = _get_last_modified(item)
    if last_modified is None:
        return False
    return last_modified > checkpoint_timestamp
