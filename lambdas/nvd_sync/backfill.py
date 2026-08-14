"""Backfill CLI for historical NVD data loading.

A standalone script that performs one-time bulk loading of NVD CVE data
into the Intelligence_Table via the NVD 2.0 REST API. Supports resumption
from the last completed year via a progress checkpoint.

The NVD yearly JSON feed files (nvdcve-2.0-{year}.json.gz) were retired by
NIST in late 2023. This module uses the live NVD 2.0 API with date-range
pagination instead, ensuring complete coverage for all years.

Usage:
    python -m lambdas.nvd_sync.backfill --env dev
    python -m lambdas.nvd_sync.backfill --env prod --start-year 2023 --end-year 2026
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections import deque
from datetime import UTC, datetime

import boto3
import urllib3
from botocore.exceptions import ClientError

from lambdas.nvd_sync.config import (
    BASE_DELAY_SECONDS,
    MAX_RETRIES,
    NVD_API_BASE_URL,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    get_ssm_api_key_path,
    get_table_name,
)
from lambdas.nvd_sync.transformer import transform_nvd_cve
from lambdas.shared.dynamo_writer import DynamoWriter
from lambdas.shared.exceptions import TransformError, WriteError

logger = logging.getLogger(__name__)

# Year range for backfill (inclusive)
BACKFILL_START_YEAR = 2016
BACKFILL_END_YEAR = 2026

# Checkpoint keys
BACKFILL_CHECKPOINT_PK = "SYSTEM#BACKFILL"
BACKFILL_CHECKPOINT_SK = "NVD"
SYNC_CHECKPOINT_PK = "SYSTEM#SYNC"
SYNC_CHECKPOINT_SK = "NVD"

# NVD API pagination
_RESULTS_PER_PAGE = 2000


# ---------------------------------------------------------------------------
# Rate limiter (identical to gap_recovery.py implementation)
# ---------------------------------------------------------------------------


class _RateLimiter:
    """Rolling window rate limiter for NVD API requests."""

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
            oldest = self._timestamps[0]
            sleep_time = self.window_seconds - (now - oldest)
            if sleep_time > 0:
                time.sleep(sleep_time)
            self._evict_expired(time.monotonic())

    def record_request(self) -> None:
        """Record that a request was made at the current time."""
        self._timestamps.append(time.monotonic())

    def _evict_expired(self, now: float) -> None:
        """Remove timestamps older than the rolling window."""
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _get_dynamodb_table(table_name: str):
    """Get a boto3 DynamoDB Table resource."""
    dynamodb = boto3.resource("dynamodb")
    return dynamodb.Table(table_name)


def _read_backfill_checkpoint(table_name: str) -> int | None:
    """Read the backfill progress checkpoint from DynamoDB.

    Returns:
        The last completed year, or None if no checkpoint exists.
    """
    table = _get_dynamodb_table(table_name)
    try:
        response = table.get_item(Key={"pk": BACKFILL_CHECKPOINT_PK, "sk": BACKFILL_CHECKPOINT_SK})
    except ClientError as e:
        logger.error("Failed to read backfill checkpoint: %s", e)
        return None

    item = response.get("Item")
    if item is None:
        return None

    year = item.get("last_completed_year")
    return int(year) if year is not None else None


def _write_backfill_checkpoint(table_name: str, year: int) -> None:
    """Update the backfill progress checkpoint after a year completes."""
    table = _get_dynamodb_table(table_name)
    now = datetime.now(UTC).isoformat()
    table.put_item(
        Item={
            "pk": BACKFILL_CHECKPOINT_PK,
            "sk": BACKFILL_CHECKPOINT_SK,
            "last_completed_year": year,
            "completed_at": now,
        }
    )
    logger.info("Updated backfill checkpoint: year=%d, completed_at=%s", year, now)


def _write_sync_checkpoint(table_name: str) -> None:
    """Set the sync checkpoint after all backfill years complete.

    This enables the Sync Lambda to begin ongoing incremental sync
    from the backfill completion time.
    """
    table = _get_dynamodb_table(table_name)
    now = datetime.now(UTC).isoformat()
    table.put_item(
        Item={
            "pk": SYNC_CHECKPOINT_PK,
            "sk": SYNC_CHECKPOINT_SK,
            "last_successful_sync": now,
            "meta_sha256": "",
        }
    )
    logger.info("Set sync checkpoint: last_successful_sync=%s", now)


# ---------------------------------------------------------------------------
# NVD API key retrieval
# ---------------------------------------------------------------------------


def _get_nvd_api_key(environment: str) -> str | None:
    """Read NVD API key from SSM Parameter Store.

    Returns:
        The API key string, or None if retrieval fails.
    """
    ssm = boto3.client("ssm")
    param_path = get_ssm_api_key_path(environment)
    try:
        response = ssm.get_parameter(Name=param_path, WithDecryption=True)
        return response["Parameter"]["Value"]
    except ClientError as e:
        logger.warning("Failed to retrieve NVD API key from SSM (%s): %s", param_path, e)
        return None


# ---------------------------------------------------------------------------
# NVD API fetching
# ---------------------------------------------------------------------------


def _fetch_page_with_retry(
    *,
    http: urllib3.PoolManager,
    api_key: str | None,
    params: dict[str, str],
    rate_limiter: _RateLimiter,
) -> dict | None:
    """Fetch a single page from the NVD 2.0 API with retry logic.

    Retries up to MAX_RETRIES times with exponential backoff.

    Returns:
        Parsed JSON response dict, or None if all retries failed.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{NVD_API_BASE_URL}?{query_string}"

    for attempt in range(MAX_RETRIES + 1):
        if attempt > 0:
            delay = BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.info(
                "Retrying NVD API request (attempt %d/%d, delay %ds)",
                attempt + 1,
                MAX_RETRIES + 1,
                delay,
            )
            time.sleep(delay)

        rate_limiter.wait_if_needed()

        try:
            response = http.request(
                "GET",
                url,
                headers=headers,
                timeout=30.0,
            )
            rate_limiter.record_request()

            if response.status == 200:
                return json.loads(response.data.decode("utf-8"))

            if response.status == 403:
                logger.warning("NVD API returned HTTP 403 — possible rate limit or invalid key")
            elif response.status == 503:
                logger.warning("NVD API returned HTTP 503 — service temporarily unavailable")
            else:
                logger.warning("NVD API returned HTTP %d", response.status)

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "NVD API request failed (attempt %d/%d): %s",
                attempt + 1,
                MAX_RETRIES + 1,
                exc,
            )

    return None


def _build_date_windows(year: int) -> list[tuple[str, str]]:
    """Split a calendar year into 120-day windows for NVD API compliance.

    The NVD 2.0 API enforces a maximum range of 120 consecutive days
    for date-range parameters. This function produces non-overlapping
    windows covering the entire year.

    Returns:
        List of (start_date, end_date) tuples in ISO 8601 format with
        UTC timezone offset as required by the NVD API.
    """
    from datetime import timedelta

    window_days = 120
    year_start = datetime(year, 1, 1, tzinfo=UTC)
    year_end = datetime(year, 12, 31, 23, 59, 59, tzinfo=UTC)

    windows: list[tuple[str, str]] = []
    current_start = year_start

    while current_start <= year_end:
        current_end = min(current_start + timedelta(days=window_days - 1), year_end)
        # NVD API expects ISO 8601 without timezone offset suffix
        start_str = current_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = current_end.strftime("%Y-%m-%dT%H:%M:%S.999")
        windows.append((start_str, end_str))
        current_start = current_end + timedelta(seconds=1)

    return windows


def _fetch_window_from_api(
    *,
    http: urllib3.PoolManager,
    api_key: str | None,
    start_date: str,
    end_date: str,
    rate_limiter: _RateLimiter,
    year: int,
    window_idx: int,
) -> list[dict] | None:
    """Fetch all CVEs published in a single date window via pagination.

    Returns:
        List of NVD 2.0 vulnerability objects, or None on fatal failure.
    """
    all_items: list[dict] = []
    start_index = 0
    total_results: int | None = None

    while True:
        params = {
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "startIndex": str(start_index),
            "resultsPerPage": str(_RESULTS_PER_PAGE),
        }

        response_data = _fetch_page_with_retry(
            http=http,
            api_key=api_key,
            params=params,
            rate_limiter=rate_limiter,
        )

        if response_data is None:
            logger.error(
                "NVD API request failed after all retries for year %d window %d (startIndex=%d)",
                year,
                window_idx,
                start_index,
            )
            return None

        if total_results is None:
            total_results = response_data.get("totalResults", 0)
            logger.info(
                "Year %d window %d (%s → %s): %d CVEs",
                year,
                window_idx,
                start_date[:10],
                end_date[:10],
                total_results,
            )

        vulnerabilities = response_data.get("vulnerabilities", [])
        all_items.extend(vulnerabilities)

        results_per_page = response_data.get("resultsPerPage", _RESULTS_PER_PAGE)
        start_index += results_per_page

        if start_index >= total_results:
            break

    return all_items


def _fetch_year_from_api(
    year: int,
    api_key: str | None,
    rate_limiter: _RateLimiter,
) -> list[dict] | None:
    """Fetch all CVEs published in a given year via the NVD 2.0 API.

    Splits the year into 120-day windows (NVD API max range) and
    paginates through each window.

    Returns:
        List of NVD 2.0 vulnerability objects, or None on fatal failure.
    """
    windows = _build_date_windows(year)
    logger.info("Year %d: split into %d date window(s)", year, len(windows))

    http = urllib3.PoolManager()
    all_items: list[dict] = []

    for idx, (start_date, end_date) in enumerate(windows):
        window_items = _fetch_window_from_api(
            http=http,
            api_key=api_key,
            start_date=start_date,
            end_date=end_date,
            rate_limiter=rate_limiter,
            year=year,
            window_idx=idx + 1,
        )

        if window_items is None:
            logger.error("Aborting year %d: window %d failed after retries", year, idx + 1)
            return None

        all_items.extend(window_items)

    logger.info("Year %d: fetched %d total CVEs from NVD API", year, len(all_items))
    return all_items


# ---------------------------------------------------------------------------
# Year processing
# ---------------------------------------------------------------------------


def _process_year(year: int, table_name: str, timestamp: str, api_key: str | None) -> bool:
    """Process a single year: fetch from API, transform, write to DynamoDB.

    Args:
        year: The year to process.
        table_name: DynamoDB table name.
        timestamp: ISO 8601 timestamp for metadata fields.
        api_key: NVD API key (or None for unauthenticated, rate-limited access).

    Returns:
        True if the year was processed successfully, False on abort.
    """
    rate_limiter = _RateLimiter()

    # Fetch all CVEs for this year from the NVD API
    vulnerabilities = _fetch_year_from_api(year, api_key, rate_limiter)

    if vulnerabilities is None:
        logger.error(
            "Aborting backfill: failed to fetch year %d from NVD API after retries",
            year,
        )
        return False

    if not vulnerabilities:
        logger.info("Year %d: no CVEs found — skipping", year)
        return True

    logger.info("Processing year %d: %d CVE items to transform", year, len(vulnerabilities))

    # Transform CVEs
    items: list[dict] = []
    skipped = 0

    for idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            logger.warning("Year %d: skipping item at index %d (not a dict)", year, idx)
            skipped += 1
            continue

        try:
            item = transform_nvd_cve(vuln, timestamp)
            items.append(item)
        except TransformError as e:
            logger.warning("Year %d: skipping malformed item at index %d: %s", year, idx, e)
            skipped += 1

    logger.info(
        "Year %d: transformed %d items, skipped %d malformed",
        year,
        len(items),
        skipped,
    )

    # Batch write to DynamoDB
    writer = DynamoWriter(table_name=table_name, max_retries=MAX_RETRIES)
    try:
        result = writer.batch_put_items(items)
        logger.info("Year %d: wrote %d items to DynamoDB", year, result.items_written)
    except WriteError as e:
        logger.error(
            "Aborting backfill: persistent UnprocessedItems for year %d: %s",
            year,
            e,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(env: str, start_year: int = BACKFILL_START_YEAR, end_year: int = BACKFILL_END_YEAR) -> int:
    """Run the backfill process for the specified environment.

    Args:
        env: Target environment ("dev" or "prod").
        start_year: First year to process (default 2016).
        end_year: Last year to process (default 2026).

    Returns:
        0 on success, 1 on failure.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    table_name = get_table_name(env)
    timestamp = datetime.now(UTC).isoformat()

    logger.info(
        "Starting NVD backfill for environment=%s, table=%s, years=%d–%d",
        env,
        table_name,
        start_year,
        end_year,
    )

    # Retrieve NVD API key from SSM (optional but recommended for throughput)
    api_key = _get_nvd_api_key(env)
    if api_key:
        logger.info("NVD API key retrieved from SSM — using authenticated rate limits")
    else:
        logger.warning(
            "No NVD API key available — using unauthenticated rate limits "
            "(5 requests per 30 seconds). Backfill will be significantly slower."
        )

    # Read backfill checkpoint to determine resume point
    last_completed = _read_backfill_checkpoint(table_name)
    if last_completed is not None and last_completed >= start_year:
        resume_year = last_completed + 1
        logger.info(
            "Resuming backfill from year %d (last completed: %d)",
            resume_year,
            last_completed,
        )
    else:
        resume_year = start_year
        logger.info("Starting backfill from year %d", resume_year)

    if resume_year > end_year:
        logger.info(
            "All years already completed (last_completed=%d). Nothing to do.",
            last_completed,
        )
        return 0

    # Process each year
    for year in range(resume_year, end_year + 1):
        logger.info("--- Processing year %d ---", year)
        success = _process_year(year, table_name, timestamp, api_key)

        if not success:
            logger.error(
                "Backfill aborted at year %d. Checkpoint preserved at last completed year.",
                year,
            )
            return 1

        # Update backfill progress checkpoint after each successful year
        _write_backfill_checkpoint(table_name, year)

    # All years complete — set the sync checkpoint
    _write_sync_checkpoint(table_name)
    logger.info(
        "Backfill complete. All years %d–%d processed successfully.",
        start_year,
        end_year,
    )
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NVD historical backfill CLI")
    parser.add_argument(
        "--env",
        required=True,
        choices=["dev", "prod"],
        help="Target environment (dev or prod)",
    )
    parser.add_argument(
        "--start-year",
        type=int,
        default=BACKFILL_START_YEAR,
        help=f"First year to process (default: {BACKFILL_START_YEAR})",
    )
    parser.add_argument(
        "--end-year",
        type=int,
        default=BACKFILL_END_YEAR,
        help=f"Last year to process (default: {BACKFILL_END_YEAR})",
    )
    args = parser.parse_args()
    sys.exit(main(args.env, args.start_year, args.end_year))
