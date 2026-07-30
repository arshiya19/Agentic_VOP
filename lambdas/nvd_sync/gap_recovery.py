"""NVD API-based gap recovery for sync gaps exceeding the modified feed's 8-day window.

When the gap between the current time and the last checkpoint is between 8 and 120 days,
this module queries the NVD 2.0 API using `lastModStartDate` to retrieve all CVEs
modified since the last checkpoint. It handles:

- SSM Parameter Store API key retrieval with in-memory caching
- Rolling-window rate limiting (max 50 requests per 30 seconds)
- Pagination through all result pages
- Exponential backoff retry on transient failures
- Abort on persistent failure without updating checkpoint
- Critical gap detection (>120 days) with CRITICAL log emission
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

import boto3
import urllib3

from lambdas.nvd_sync.config import (
    BASE_DELAY_SECONDS,
    CRITICAL_GAP_DAYS,
    MAX_RETRIES,
    NVD_API_BASE_URL,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    get_ssm_api_key_path,
)
from lambdas.shared.emf_logger import EmfLogger

# ---------------------------------------------------------------------------
# Module-level API key cache (persists across warm Lambda invocations)
# ---------------------------------------------------------------------------
_cached_api_key: str | None = None

# NVD API maximum results per page
_RESULTS_PER_PAGE = 2000


@dataclass
class GapRecoveryResult:
    """Result of gap recovery execution."""

    success: bool
    cve_items: list[dict] = field(default_factory=list)
    total_retrieved: int = 0
    error_message: str | None = None


class RateLimiter:
    """Rolling window rate limiter for NVD API requests.

    Tracks request timestamps in a deque. Before each request, removes
    timestamps older than the window. If the window has reached capacity,
    sleeps until the oldest request falls outside the window.
    """

    def __init__(
        self,
        max_requests: int = RATE_LIMIT_REQUESTS,
        window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()

    def wait_if_needed(self) -> None:
        """Block until a request slot is available in the rolling window."""
        now = time.monotonic()
        self._evict_expired(now)

        if len(self._timestamps) >= self.max_requests:
            # Wait until the oldest request falls outside the window
            oldest = self._timestamps[0]
            sleep_time = self.window_seconds - (now - oldest)
            if sleep_time > 0:
                time.sleep(sleep_time)
            # After sleeping, evict again
            self._evict_expired(time.monotonic())

    def record_request(self) -> None:
        """Record that a request was made at the current time."""
        self._timestamps.append(time.monotonic())

    def _evict_expired(self, now: float) -> None:
        """Remove timestamps older than the rolling window."""
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


def _get_nvd_api_key(environment: str) -> str | None:
    """Read NVD API key from SSM Parameter Store, cached after first read.

    Args:
        environment: Deployment environment (dev/prod).

    Returns:
        The API key string, or None if retrieval fails.
    """
    global _cached_api_key
    if _cached_api_key is not None:
        return _cached_api_key

    ssm = boto3.client("ssm")
    param_path = get_ssm_api_key_path(environment)
    try:
        response = ssm.get_parameter(Name=param_path, WithDecryption=True)
        _cached_api_key = response["Parameter"]["Value"]
        return _cached_api_key
    except Exception:  # noqa: BLE001 — SSM may raise various SDK/network errors
        return None


def recover_gap(
    checkpoint_timestamp: str,
    environment: str,
    logger: EmfLogger,
    context=None,
) -> GapRecoveryResult:
    """Execute gap recovery via NVD API.

    Queries the NVD 2.0 API for all CVEs modified between the checkpoint
    timestamp and now. Paginates through all pages, rate-limits requests,
    and retries transient failures.

    Args:
        checkpoint_timestamp: ISO 8601 timestamp of last successful sync.
        environment: Deployment environment (dev/prod).
        logger: EMF logger for structured logging.
        context: Optional Lambda context for timeout safety checks.

    Returns:
        GapRecoveryResult with retrieved CVE items or error info.
    """
    # --- Check for critical gap (>120 days) ---
    gap_days = _compute_gap_days(checkpoint_timestamp)
    if gap_days is not None and gap_days >= CRITICAL_GAP_DAYS:
        logger.critical(
            "GAP_RECOVERY",
            f"Critical gap detected: {gap_days} days since last sync. "
            f"Exceeds {CRITICAL_GAP_DAYS}-day threshold. Manual re-backfill required.",
            gap_days=gap_days,
            checkpoint=checkpoint_timestamp,
        )
        return GapRecoveryResult(
            success=False,
            error_message=(
                f"Critical gap: {gap_days} days exceeds {CRITICAL_GAP_DAYS}-day threshold. "
                "Manual re-backfill required."
            ),
        )

    # --- Retrieve NVD API key from SSM ---
    api_key = _get_nvd_api_key(environment)
    if api_key is None:
        logger.error(
            "GAP_RECOVERY",
            "Failed to retrieve NVD API key from SSM Parameter Store. Skipping gap recovery.",
            environment=environment,
            ssm_path=get_ssm_api_key_path(environment),
        )
        return GapRecoveryResult(
            success=False,
            error_message="Failed to retrieve NVD API key from SSM Parameter Store.",
        )

    # --- Prepare query parameters ---
    now_iso = datetime.now(UTC).isoformat(timespec="milliseconds")
    rate_limiter = RateLimiter()
    http = urllib3.PoolManager()

    all_cve_items: list[dict] = []
    start_index = 0
    total_results: int | None = None

    logger.info(
        "GAP_RECOVERY",
        f"Starting gap recovery from checkpoint {checkpoint_timestamp}",
        checkpoint=checkpoint_timestamp,
        end_date=now_iso,
        gap_days=gap_days,
    )

    # --- Paginate through all result pages ---
    while True:
        # Rate limit before making a request
        rate_limiter.wait_if_needed()

        # Make the API request with retries
        response_data = _fetch_page_with_retry(
            http=http,
            api_key=api_key,
            start_date=checkpoint_timestamp,
            end_date=now_iso,
            start_index=start_index,
            logger=logger,
        )

        if response_data is None:
            # All retries exhausted — abort without updating checkpoint
            logger.error(
                "GAP_RECOVERY",
                "Gap recovery aborted: NVD API request failed after all retries.",
                start_index=start_index,
                items_retrieved_so_far=len(all_cve_items),
            )
            return GapRecoveryResult(
                success=False,
                cve_items=[],
                total_retrieved=0,
                error_message="NVD API request failed after all retries.",
            )

        # Record the request timestamp for rate limiting
        rate_limiter.record_request()

        # Extract pagination info
        if total_results is None:
            total_results = response_data.get("totalResults", 0)
            logger.info(
                "GAP_RECOVERY",
                f"NVD API reports {total_results} total modified CVEs in gap window.",
                total_results=total_results,
            )

        # Extract CVE items from this page
        vulnerabilities = response_data.get("vulnerabilities", [])
        all_cve_items.extend(vulnerabilities)

        # Move to next page
        results_per_page = response_data.get("resultsPerPage", _RESULTS_PER_PAGE)
        start_index += results_per_page

        # Check if we've retrieved all pages
        if start_index >= total_results:
            break

    logger.info(
        "GAP_RECOVERY",
        f"Gap recovery complete: retrieved {len(all_cve_items)} CVE items.",
        total_retrieved=len(all_cve_items),
        total_results=total_results,
    )

    return GapRecoveryResult(
        success=True,
        cve_items=all_cve_items,
        total_retrieved=len(all_cve_items),
    )


def _fetch_page_with_retry(
    *,
    http: urllib3.PoolManager,
    api_key: str,
    start_date: str,
    end_date: str,
    start_index: int,
    logger: EmfLogger,
) -> dict | None:
    """Fetch a single page from the NVD API with retry logic.

    Retries up to MAX_RETRIES times with exponential backoff (1s, 2s, 4s).

    Args:
        http: urllib3 PoolManager for making HTTP requests.
        api_key: NVD API key for authentication.
        start_date: ISO 8601 start date for lastModStartDate.
        end_date: ISO 8601 end date for lastModEndDate.
        start_index: Pagination offset.
        logger: EMF logger for structured logging.

    Returns:
        Parsed JSON response dict, or None if all retries failed.
    """
    import json

    headers = {"apiKey": api_key}
    params = {
        "lastModStartDate": start_date,
        "lastModEndDate": end_date,
        "startIndex": str(start_index),
        "resultsPerPage": str(_RESULTS_PER_PAGE),
    }

    # Build query string
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{NVD_API_BASE_URL}?{query_string}"

    for attempt in range(MAX_RETRIES + 1):
        if attempt > 0:
            delay = BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "GAP_RECOVERY",
                f"Retrying NVD API request (attempt {attempt + 1}/{MAX_RETRIES + 1}, "
                f"delay {delay}s)",
                attempt=attempt + 1,
                delay_seconds=delay,
                start_index=start_index,
            )
            time.sleep(delay)

        try:
            response = http.request(
                "GET",
                url,
                headers=headers,
                timeout=30.0,
            )

            if response.status == 200:
                return json.loads(response.data.decode("utf-8"))

            # Non-200 status — log and retry
            logger.warning(
                "GAP_RECOVERY",
                f"NVD API returned HTTP {response.status}",
                http_status=response.status,
                attempt=attempt + 1,
                start_index=start_index,
            )

        except Exception as exc:  # noqa: BLE001 — catch-all for network/urllib3 transient errors
            logger.warning(
                "GAP_RECOVERY",
                f"NVD API request failed: {exc}",
                error=str(exc),
                attempt=attempt + 1,
                start_index=start_index,
            )

    # All retries exhausted
    return None


def _compute_gap_days(checkpoint_timestamp: str) -> int | None:
    """Compute the number of days between checkpoint and now.

    Args:
        checkpoint_timestamp: ISO 8601 timestamp string.

    Returns:
        Number of days as an integer, or None if parsing fails.
    """
    try:
        checkpoint_dt = datetime.fromisoformat(checkpoint_timestamp)
        if checkpoint_dt.tzinfo is None:
            checkpoint_dt = checkpoint_dt.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        return (now - checkpoint_dt).days
    except (ValueError, TypeError):
        return None
