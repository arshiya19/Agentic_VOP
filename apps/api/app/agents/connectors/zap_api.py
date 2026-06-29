"""OWASP ZAP connector — triggers a scan and fetches alerts from a ZAP instance.

Full flow when VOP triggers a fetch:
  1. Spider (crawl) the target URL to discover pages
  2. Run an active scan against discovered pages
  3. Fetch all alerts (findings) from ZAP

Prerequisites:
  - ZAP running in daemon mode (Docker or local)
  - A target URL to scan (e.g., http://localhost:3000 for Juice Shop)

Configuration (in connection_registry):
  endpoint   : ZAP API base URL, e.g. "http://localhost:8080"
  metadata:
    connector_type : "zap_api"
    api_key        : ZAP API key
    target_url     : URL to scan (e.g. "http://host.docker.internal:3000")
    spider_timeout : max seconds to wait for spider (default: 120)
    scan_timeout   : max seconds to wait for active scan (default: 600)
    skip_scan      : if true, only fetch existing alerts without triggering a new scan
"""

from __future__ import annotations

import time

import httpx


_DEFAULT_BASE_URL = "http://localhost:8080"
_PAGE_SIZE = 100
_SPIDER_POLL_INTERVAL = 5  # seconds between status checks
_SCAN_POLL_INTERVAL = 10


def fetch(registry_entry: dict, last_fetched_at: str | None = None) -> list[dict]:  # noqa: ARG001
    """Run a full ZAP scan cycle and return alerts."""
    base_url = (registry_entry.get("endpoint") or _DEFAULT_BASE_URL).rstrip("/")
    metadata = registry_entry.get("metadata") or {}
    api_key = metadata.get("api_key", "")
    target_url = metadata.get("target_url", "")
    skip_scan = metadata.get("skip_scan", False)
    spider_timeout = int(metadata.get("spider_timeout", 120))
    scan_timeout = int(metadata.get("scan_timeout", 600))

    if not target_url and not skip_scan:
        raise ValueError(
            "zap_api connector: 'target_url' is required in metadata "
            "unless 'skip_scan' is true. Set it to the URL you want ZAP to scan."
        )

    params: dict[str, str] = {}
    if api_key:
        params["apikey"] = api_key

    with httpx.Client(timeout=60) as client:
        if not skip_scan:
            # Step 1: Spider (crawl) the target
            _run_spider(client, base_url, target_url, params, spider_timeout)

            # Step 2: Active scan
            _run_active_scan(client, base_url, target_url, params, scan_timeout)

        # Step 3: Fetch all alerts
        return _fetch_alerts(client, base_url, params)


def _run_spider(
    client: httpx.Client,
    base_url: str,
    target_url: str,
    params: dict[str, str],
    timeout_sec: int,
) -> None:
    """Start the ZAP spider and wait for it to complete."""
    spider_params = {**params, "url": target_url}
    resp = client.get(f"{base_url}/JSON/spider/action/scan/", params=spider_params)

    if resp.status_code != 200:
        raise RuntimeError(f"ZAP spider failed to start: HTTP {resp.status_code} — {resp.text[:200]}")

    scan_id = resp.json().get("scan")
    if not scan_id:
        raise RuntimeError(f"ZAP spider returned no scan ID: {resp.json()}")

    # Poll until complete
    elapsed = 0
    while elapsed < timeout_sec:
        time.sleep(_SPIDER_POLL_INTERVAL)
        elapsed += _SPIDER_POLL_INTERVAL

        status_resp = client.get(
            f"{base_url}/JSON/spider/view/status/",
            params={**params, "scanId": scan_id},
        )
        if status_resp.status_code == 200:
            progress = int(status_resp.json().get("status", "0"))
            if progress >= 100:
                return

    # Timeout — continue anyway, partial crawl is still useful
    return


def _run_active_scan(
    client: httpx.Client,
    base_url: str,
    target_url: str,
    params: dict[str, str],
    timeout_sec: int,
) -> None:
    """Start ZAP active scan and wait for it to complete."""
    scan_params = {**params, "url": target_url}
    resp = client.get(f"{base_url}/JSON/ascan/action/scan/", params=scan_params)

    if resp.status_code != 200:
        raise RuntimeError(
            f"ZAP active scan failed to start: HTTP {resp.status_code} — {resp.text[:200]}"
        )

    scan_id = resp.json().get("scan")
    if not scan_id:
        raise RuntimeError(f"ZAP active scan returned no scan ID: {resp.json()}")

    # Poll until complete
    elapsed = 0
    while elapsed < timeout_sec:
        time.sleep(_SCAN_POLL_INTERVAL)
        elapsed += _SCAN_POLL_INTERVAL

        status_resp = client.get(
            f"{base_url}/JSON/ascan/view/status/",
            params={**params, "scanId": scan_id},
        )
        if status_resp.status_code == 200:
            progress = int(status_resp.json().get("status", "0"))
            if progress >= 100:
                return

    # Timeout — continue anyway, partial results are still valuable
    return


def _fetch_alerts(
    client: httpx.Client,
    base_url: str,
    params: dict[str, str],
) -> list[dict]:
    """Paginate through all ZAP alerts and return them as raw rows."""
    all_alerts: list[dict] = []
    start = 0

    while True:
        page_params = {**params, "start": str(start), "count": str(_PAGE_SIZE)}
        resp = client.get(f"{base_url}/JSON/alert/view/alerts/", params=page_params)

        if resp.status_code != 200:
            raise RuntimeError(
                f"ZAP alerts API returned HTTP {resp.status_code}: {resp.text[:300]}"
            )

        alerts = resp.json().get("alerts", [])
        if not alerts:
            break

        for alert in alerts:
            all_alerts.append(
                {
                    "alert_id": alert.get("id"),
                    "plugin_id": alert.get("pluginId"),
                    "alert_name": alert.get("alert") or alert.get("name"),
                    "risk": alert.get("risk"),  # "High", "Medium", "Low", "Informational"
                    "confidence": alert.get("confidence"),
                    "description": alert.get("description"),
                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),
                    "cwe_id": alert.get("cweid"),
                    "wasc_id": alert.get("wascid"),
                    "url": alert.get("url"),
                    "method": alert.get("method"),
                    "param": alert.get("param"),
                    "attack": alert.get("attack"),
                    "evidence": alert.get("evidence"),
                    "other_info": alert.get("other"),
                    "tags": alert.get("tags") or {},
                }
            )

        if len(alerts) < _PAGE_SIZE:
            break

        start += _PAGE_SIZE

    return all_alerts
