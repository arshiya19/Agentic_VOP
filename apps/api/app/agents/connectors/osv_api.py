"""OSV.dev connector — public vulnerability database, no auth required.

For each row in `monitored_packages`, POST to https://api.osv.dev/v1/query and
return one record per matching vulnerability. Each returned row is augmented
with the package context (so Sub-Agent 1's prompt can build asset_identity +
package fields without re-joining).

Watermark behavior: if last_fetched_at is provided, we only emit vulnerabilities
whose `modified` timestamp is strictly newer than the watermark.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ...db import supabase_admin


_OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        s = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def fetch(registry_entry: dict, last_fetched_at: str | None = None) -> list[dict]:
    """Query OSV for every monitored package; return one record per vulnerability."""
    sb = supabase_admin()

    packages = sb.table("monitored_packages").select("*").eq("enabled", True).execute().data or []

    if not packages:
        return []

    cutoff = _parse_iso(last_fetched_at)
    base_url = registry_entry.get("endpoint") or _OSV_QUERY_URL

    all_records: list[dict] = []

    with httpx.Client(timeout=30) as client:
        for pkg in packages:
            try:
                resp = client.post(
                    base_url,
                    json={
                        "package": {
                            "name": pkg["name"],
                            "ecosystem": pkg["ecosystem"],
                        },
                        "version": pkg["version"],
                    },
                )
                if resp.status_code != 200:
                    continue
                vulns = resp.json().get("vulns", []) or []
            except Exception:  # nosec B110 — intentional: skip failed package queries, continue to next package  # noqa: S112
                continue

            for v in vulns:
                # Watermark: skip vulns we've already seen
                modified = _parse_iso(v.get("modified"))
                if cutoff is not None and modified is not None and modified <= cutoff:
                    continue

                # Pull the GitHub-database severity if present (easy mapping for the LLM)
                db_specific = v.get("database_specific") or {}
                github_severity = db_specific.get("severity")

                all_records.append(
                    {
                        "osv_id": v.get("id"),
                        "aliases": v.get("aliases", []) or [],
                        "summary": v.get("summary"),
                        "details": v.get("details"),
                        "published": v.get("published"),
                        "modified": v.get("modified"),
                        "github_severity": github_severity,
                        "severity_entries": v.get("severity", []) or [],
                        "affected": v.get("affected", []) or [],
                        "references": v.get("references", []) or [],
                        "queried_package_name": pkg["name"],
                        "queried_package_version": pkg["version"],
                        "queried_package_ecosystem": pkg["ecosystem"],
                        "queried_package_label": pkg.get("label"),
                    }
                )

    return all_records
