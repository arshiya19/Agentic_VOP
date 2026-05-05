"""Real Tenable / Nessus API connector.

Talks to a Nessus instance (typically https://localhost:8834) using the
classic /scans/* + /plugins/* REST endpoints with X-ApiKeys auth.

Output shape matches the legacy `tenable` table — one row per (scan, host,
plugin) tuple — so Sub-Agent 1's existing tenable prompt normalizes it
without any change.

Watermark behavior: if last_fetched_at is provided, we filter to only scans
whose `last_modification_date` is strictly newer than the watermark.
"""

from __future__ import annotations

import time
from datetime import datetime

import httpx

from ...config import settings


_DEFAULT_BASE_URL = "https://localhost:8834"
_DEFAULT_SCAN_LIMIT = 5  # cap per run so demos don't take forever


def _headers() -> dict[str, str]:
    if not settings.tenable_access_key or not settings.tenable_secret_key:
        raise RuntimeError(
            "Missing TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY in environment"
        )
    return {
        "X-ApiKeys": (
            f"accessKey={settings.tenable_access_key}; "
            f"secretKey={settings.tenable_secret_key}"
        ),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _parse_watermark(last_fetched_at: str | None) -> float | None:
    """Convert ISO 8601 watermark to UNIX epoch seconds (Nessus uses epoch)."""
    if not last_fetched_at:
        return None
    try:
        s = last_fetched_at.replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def fetch(registry_entry: dict, last_fetched_at: str | None = None) -> list[dict]:
    """Hit Nessus and return raw vulnerability records ready for Sub-Agent 1."""
    base_url = registry_entry.get("endpoint") or _DEFAULT_BASE_URL
    metadata = registry_entry.get("metadata") or {}
    scan_limit = int(metadata.get("scan_limit", _DEFAULT_SCAN_LIMIT))

    cutoff_epoch = _parse_watermark(last_fetched_at)

    # Nessus typically uses a self-signed cert on localhost.
    # verify=False is intentional here — Nessus on localhost uses a self-signed
    # cert by design. This connector is never used against public endpoints.
    client = httpx.Client(verify=False, timeout=60, headers=_headers())  # nosec B501  # noqa: S501

    plugin_cache: dict[int, dict] = {}

    def get_plugin_details(plugin_id: int) -> dict:
        if plugin_id in plugin_cache:
            return plugin_cache[plugin_id]
        try:
            resp = client.get(f"{base_url}/plugins/plugin/{plugin_id}")
            if resp.status_code != 200:
                plugin_cache[plugin_id] = {}
                return {}
            attributes = resp.json().get("attributes", []) or []
            plugin_data = {
                a.get("attribute_name"): a.get("attribute_value")
                for a in attributes
                if a.get("attribute_name")
            }
            plugin_cache[plugin_id] = plugin_data
            time.sleep(0.05)  # gentle on the local Nessus
            return plugin_data
        except Exception:  # nosec B110 — intentional: cache empty result and continue on any plugin fetch error  # noqa: S112
            plugin_cache[plugin_id] = {}
            return {}

    try:
        # 1. List scans
        scans = client.get(f"{base_url}/scans").json().get("scans", []) or []

        # Apply watermark — only scans whose last_modification_date is newer
        if cutoff_epoch is not None:
            scans = [
                s
                for s in scans
                if (s.get("last_modification_date") or 0) > cutoff_epoch
            ]

        scans = scans[:scan_limit]

        all_vulns: list[dict] = []

        for scan in scans:
            scan_id = scan.get("id")
            if not scan_id:
                continue

            # 2. Scan details
            details = client.get(f"{base_url}/scans/{scan_id}").json()
            info = details.get("info", {}) or {}
            scan_start = info.get("scan_start")
            scan_date = (
                datetime.fromtimestamp(scan_start, tz=datetime.UTC).strftime("%Y-%m-%d")
                if scan_start
                else datetime.now(datetime.UTC).strftime("%Y-%m-%d")
            )

            hosts = details.get("hosts", []) or []
            vulns = details.get("vulnerabilities", []) or []

            for host in hosts:
                host_id = host.get("host_id")
                hostname = host.get("hostname", "") or ""
                if not host_id:
                    continue

                for vuln in vulns:
                    plugin_id = vuln.get("plugin_id")
                    if not plugin_id:
                        continue

                    # 3. Per-host vulnerability details
                    try:
                        vuln_resp = client.get(
                            f"{base_url}/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}",
                            timeout=30,
                        )
                        if vuln_resp.status_code != 200:
                            continue
                        outputs = vuln_resp.json().get("outputs", []) or []
                        if not outputs:
                            continue
                    except Exception:  # nosec B110 — intentional: skip individual vuln fetch failures, continue scan  # noqa: S112
                        continue

                    plugin_info = get_plugin_details(plugin_id)
                    cve_str = (plugin_info.get("cve") or "").strip()
                    cve_list = [c.strip() for c in cve_str.split(",") if c.strip()]

                    for output in outputs:
                        ports = output.get("ports") or {}
                        plugin_output = output.get("plugin_output", "") or ""
                        port = ""
                        protocol = ""
                        if ports:
                            port_key = next(iter(ports.keys()))
                            parts = port_key.split(" / ")
                            port = parts[0] if len(parts) >= 1 else ""
                            protocol = parts[1] if len(parts) >= 2 else ""

                        all_vulns.append(
                            {
                                "plugin_id": str(plugin_id),
                                "plugin_name": vuln.get("plugin_name", "") or "",
                                "severity": vuln.get("severity", 0),
                                "hostname": hostname,
                                "port": port,
                                "protocol": protocol,
                                "plugin_output": plugin_output,
                                "scan_id": str(scan_id),
                                "scan_name": scan.get("name", "") or "",
                                "scan_date": scan_date,
                                "description": plugin_info.get("description", "") or "",
                                "solution": plugin_info.get("solution", "") or "",
                                "cve": cve_list,
                                "cvss_base_score": plugin_info.get("cvss_base_score"),
                                "cvss3_base_score": plugin_info.get("cvss3_base_score"),
                            }
                        )

        return all_vulns

    finally:
        client.close()
