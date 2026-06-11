"""Backfill CLI for historical NVD data loading.

A standalone script that performs one-time bulk loading of NVD yearly
JSON feed files into the Intelligence_Table. Supports resumption from
the last completed year via a progress checkpoint.

Usage:
    python -m lambdas.nvd_sync.backfill --env dev
    python -m lambdas.nvd_sync.backfill --env prod --start-year 2023 --end-year 2026
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone

from lambdas.nvd_sync.config import (
    MAX_RETRIES,
    NVD_YEARLY_FEED_URL_PATTERN,
    get_table_name,
)
from lambdas.nvd_sync.transformer import transform_nvd_cve
from lambdas.shared.dynamo_writer import DynamoWriter
from lambdas.shared.exceptions import FeedDownloadError, TransformError, WriteError
from lambdas.shared.feed_ingestion import download_and_decompress, parse_json_feed

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Year range for backfill (inclusive)
BACKFILL_START_YEAR = 2016
BACKFILL_END_YEAR = 2026

# Checkpoint keys
BACKFILL_CHECKPOINT_PK = "SYSTEM#BACKFILL"
BACKFILL_CHECKPOINT_SK = "NVD"
SYNC_CHECKPOINT_PK = "SYSTEM#SYNC"
SYNC_CHECKPOINT_SK = "NVD"

# Download retry configuration
DOWNLOAD_MAX_RETRIES = 3
DOWNLOAD_BASE_DELAY_SECONDS = 1

# Backfill max decompressed size (500 MB — larger than Lambda's 200 MB limit
# because the CLI runs locally with ample memory)
BACKFILL_MAX_FEED_SIZE = 500_000_000


def _get_dynamodb_table(table_name: str):
    """Get a boto3 DynamoDB Table resource."""
    dynamodb = boto3.resource("dynamodb")
    return dynamodb.Table(table_name)


def _read_backfill_checkpoint(table_name: str) -> int | None:
    """Read the backfill progress checkpoint from DynamoDB.

    Args:
        table_name: Name of the DynamoDB table.

    Returns:
        The last completed year, or None if no checkpoint exists.
    """
    table = _get_dynamodb_table(table_name)
    try:
        response = table.get_item(
            Key={"pk": BACKFILL_CHECKPOINT_PK, "sk": BACKFILL_CHECKPOINT_SK}
        )
    except ClientError as e:
        logger.error("Failed to read backfill checkpoint: %s", e)
        return None

    item = response.get("Item")
    if item is None:
        return None

    year = item.get("last_completed_year")
    return int(year) if year is not None else None


def _write_backfill_checkpoint(table_name: str, year: int) -> None:
    """Update the backfill progress checkpoint after a year completes.

    Args:
        table_name: Name of the DynamoDB table.
        year: The year that just completed successfully.
    """
    table = _get_dynamodb_table(table_name)
    now = datetime.now(timezone.utc).isoformat()
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

    Args:
        table_name: Name of the DynamoDB table.
    """
    table = _get_dynamodb_table(table_name)
    now = datetime.now(timezone.utc).isoformat()
    table.put_item(
        Item={
            "pk": SYNC_CHECKPOINT_PK,
            "sk": SYNC_CHECKPOINT_SK,
            "last_successful_sync": now,
            "meta_sha256": "",
        }
    )
    logger.info("Set sync checkpoint: last_successful_sync=%s", now)


def _download_yearly_feed(year: int) -> bytes:
    """Download and decompress a yearly NVD feed with retry logic.

    Retries up to DOWNLOAD_MAX_RETRIES times with exponential backoff
    on download failure.

    Args:
        year: The year to download the feed for.

    Returns:
        Decompressed feed data as bytes.

    Raises:
        FeedDownloadError: If all retry attempts are exhausted.
    """
    url = NVD_YEARLY_FEED_URL_PATTERN.format(year=year)
    last_error: FeedDownloadError | None = None

    for attempt in range(DOWNLOAD_MAX_RETRIES):
        if attempt > 0:
            delay = DOWNLOAD_BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.info(
                "Retrying download for year %d (attempt %d/%d, delay %.1fs)",
                year,
                attempt + 1,
                DOWNLOAD_MAX_RETRIES,
                delay,
            )
            time.sleep(delay)

        try:
            data = download_and_decompress(url, max_size=BACKFILL_MAX_FEED_SIZE)
            logger.info(
                "Downloaded and decompressed feed for year %d (%d bytes)",
                year,
                len(data),
            )
            return data
        except FeedDownloadError as e:
            last_error = e
            logger.warning(
                "Download failed for year %d (attempt %d/%d): %s",
                year,
                attempt + 1,
                DOWNLOAD_MAX_RETRIES,
                e,
            )

    # All retries exhausted
    raise last_error  # type: ignore[misc]


def _process_year(year: int, table_name: str, timestamp: str) -> bool:
    """Process a single yearly feed: download, transform, write.

    Args:
        year: The year to process.
        table_name: DynamoDB table name.
        timestamp: ISO 8601 timestamp for metadata fields.

    Returns:
        True if the year was processed successfully, False on abort.
    """
    # Download with retries
    try:
        raw_data = _download_yearly_feed(year)
    except FeedDownloadError as e:
        logger.error(
            "Aborting backfill: failed to download year %d after %d retries: %s",
            year,
            DOWNLOAD_MAX_RETRIES,
            e,
        )
        return False

    # Parse JSON feed
    try:
        feed = parse_json_feed(raw_data)
    except FeedDownloadError as e:
        logger.error("Aborting backfill: failed to parse feed for year %d: %s", year, e)
        return False

    # Extract vulnerabilities array (NVD 2.0 format)
    vulnerabilities = feed.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        logger.error(
            "Aborting backfill: 'vulnerabilities' field is not a list for year %d",
            year,
        )
        return False

    logger.info("Processing year %d: %d CVE items", year, len(vulnerabilities))

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
            logger.warning(
                "Year %d: skipping malformed item at index %d: %s", year, idx, e
            )
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


def main(
    env: str, start_year: int = BACKFILL_START_YEAR, end_year: int = BACKFILL_END_YEAR
) -> int:
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
    timestamp = datetime.now(timezone.utc).isoformat()

    logger.info(
        "Starting NVD backfill for environment=%s, table=%s, years=%d–%d",
        env,
        table_name,
        start_year,
        end_year,
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
        success = _process_year(year, table_name, timestamp)

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
