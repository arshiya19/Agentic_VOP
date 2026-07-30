"""DynamoDB batch writer with retry logic and conditional writes.

Provides efficient batch writing with automatic partitioning into
groups of 25 (DynamoDB limit), exponential backoff retries for
unprocessed items, and conditional writes to prevent overwriting
newer data from other sources.
"""

import logging
import time
from dataclasses import dataclass, field
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

from lambdas.shared.exceptions import WriteError

logger = logging.getLogger(__name__)

BATCH_SIZE = 25
BASE_DELAY_SECONDS = 1
MAX_RETRIES_DEFAULT = 3


def _prepare_item_for_dynamo(item: dict) -> dict:
    """Recursively prepare an item for DynamoDB Table resource write.

    - Converts float to Decimal (required by boto3 Table resource)
    - Converts int to Decimal for numeric fields
    - Removes keys with None values at all levels
    - Passes through strings, lists, and nested dicts recursively
    """
    cleaned = {}
    for key, value in item.items():
        if value is None:
            # Skip None values — DynamoDB Table resource doesn't accept them
            # If you need to store explicit nulls, they'd need special handling
            continue
        cleaned[key] = _convert_value(value)
    return cleaned


def _convert_value(value):
    """Convert a single value for DynamoDB compatibility."""
    if value is None:
        return None
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, int) and not isinstance(value, bool):
        return value  # boto3 handles int natively
    if isinstance(value, dict):
        return _prepare_item_for_dynamo(value)
    if isinstance(value, list):
        return [_convert_value(v) for v in value if v is not None]
    return value


@dataclass
class WriteResult:
    """Result of a batch write operation."""

    items_written: int = 0
    items_failed: int = 0
    unprocessed_items: list[dict] = field(default_factory=list)


class DynamoWriter:
    """DynamoDB batch writer with retry and conditional write support.

    Writes items in batches of 25 using BatchWriteItem for efficiency,
    and supports conditional updates via individual UpdateItem calls
    to prevent overwriting newer data.
    """

    def __init__(self, table_name: str, max_retries: int = MAX_RETRIES_DEFAULT):
        """Initialize the DynamoDB writer.

        Args:
            table_name: Name of the DynamoDB table to write to.
            max_retries: Maximum number of retries for unprocessed items.
        """
        self.table_name = table_name
        self.max_retries = max_retries
        self._client = boto3.client("dynamodb")
        self._resource = boto3.resource("dynamodb")
        self._table = self._resource.Table(table_name)

    def batch_put_items(self, items: list[dict]) -> WriteResult:
        """Write items in batches of 25 with retry logic.

        Uses DynamoDB BatchWriteItem for efficient bulk writes.
        Retries unprocessed items up to max_retries times with
        exponential backoff (1s, 2s, 4s).

        Args:
            items: List of DynamoDB item dicts to write.

        Returns:
            WriteResult with items_written, items_failed, unprocessed_items.

        Raises:
            WriteError: If all retries are exhausted and items remain unprocessed.
        """
        if not items:
            return WriteResult()

        result = WriteResult()
        batches = self._partition(items)

        for batch in batches:
            written, failed, unprocessed = self._write_batch_with_retry(batch)
            result.items_written += written
            result.items_failed += failed
            result.unprocessed_items.extend(unprocessed)

        if result.unprocessed_items:
            raise WriteError(
                source="DynamoDB",
                operation="batch_put_items",
                message=(
                    f"Exhausted {self.max_retries} retries with "
                    f"{len(result.unprocessed_items)} unprocessed items"
                ),
            )

        return result

    def batch_update_source(self, updates: list[dict], source: str) -> WriteResult:
        """Update source-specific fields with conditional write (newer wins).

        Uses individual UpdateItem calls with a ConditionExpression to
        prevent overwriting newer data. Each update must contain 'pk', 'sk',
        and the source-specific data fields along with an 'updated_at'
        timestamp for comparison.

        Args:
            updates: List of update dicts, each containing:
                - pk: Partition key value
                - sk: Sort key value
                - data: Dict of source-specific fields to update
                - updated_at: ISO 8601 timestamp for the update
            source: Source name (e.g., "nvd", "epss", "kev").

        Returns:
            WriteResult with items_written, items_failed, unprocessed_items.

        Raises:
            WriteError: If retries are exhausted for any item.
        """
        if not updates:
            return WriteResult()

        result = WriteResult()

        for update in updates:
            success = self._conditional_update_item(update, source)
            if success:
                result.items_written += 1
            else:
                result.items_failed += 1
                result.unprocessed_items.append(update)

        if result.unprocessed_items:
            raise WriteError(
                source="DynamoDB",
                operation="batch_update_source",
                message=(
                    f"Failed to update {len(result.unprocessed_items)} items for source '{source}'"
                ),
            )

        return result

    def _partition(self, items: list[dict]) -> list[list[dict]]:
        """Partition items into batches of BATCH_SIZE (25).

        Args:
            items: Full list of items to partition.

        Returns:
            List of batches, each containing at most 25 items.
        """
        return [items[i : i + BATCH_SIZE] for i in range(0, len(items), BATCH_SIZE)]

    def _write_batch_with_retry(self, batch: list[dict]) -> tuple[int, int, list[dict]]:
        """Write a single batch with exponential backoff retry.

        Uses the DynamoDB Table resource batch_writer which accepts plain
        Python dicts (high-level format) and handles serialization internally.

        Args:
            batch: List of items (max 25) to write.

        Returns:
            Tuple of (items_written, items_failed, unprocessed_items).
        """
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                delay = BASE_DELAY_SECONDS * (2 ** (attempt - 1))
                logger.info(
                    "Retrying %d items (attempt %d/%d, delay %.1fs)",
                    len(batch),
                    attempt,
                    self.max_retries,
                    delay,
                )
                time.sleep(delay)

            try:
                with self._table.batch_writer() as writer:
                    for item in batch:
                        cleaned = _prepare_item_for_dynamo(item)
                        writer.put_item(Item=cleaned)
                # batch_writer raises no error on success
                return len(batch), 0, []
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                logger.error(
                    "DynamoDB batch write failed: %s - %s",
                    error_code,
                    e.response["Error"]["Message"],
                )
                if attempt == self.max_retries:
                    return 0, len(batch), batch
                continue
            except Exception as e:  # noqa: BLE001 — last-resort catch for unexpected DynamoDB errors
                logger.error("Unexpected error during batch write: %s", e)
                if attempt == self.max_retries:
                    return 0, len(batch), batch
                continue

        # All retries exhausted
        return 0, len(batch), batch

    def _conditional_update_item(self, update: dict, source: str) -> bool:
        """Update a single item with conditional write to prevent overwriting newer data.

        Uses ConditionExpression: attribute_not_exists(pk) OR metadata.updated_at < :new_ts

        Args:
            update: Dict with pk, sk, data, and updated_at fields.
            source: Source identifier (e.g., "nvd", "epss").

        Returns:
            True if the update succeeded, False otherwise.
        """
        pk = update["pk"]
        sk = update["sk"]
        data = update["data"]
        updated_at = update["updated_at"]

        # Build UpdateExpression to set source-specific fields and metadata
        update_expression_parts = [
            f"SET #{source} = :source_data",
            "metadata.updated_at = :new_ts",
        ]

        # Add source to sources_present list if not already there
        update_expression_parts.append(
            "metadata.sources_present = list_append("
            "if_not_exists(metadata.sources_present, :empty_list), :source_list)"
        )

        update_expression = ", ".join(update_expression_parts)

        expression_attribute_names = {
            f"#{source}": source,
        }

        expression_attribute_values = {
            ":source_data": data,
            ":new_ts": updated_at,
            ":empty_list": [],
            ":source_list": [source],
        }

        condition_expression = "attribute_not_exists(pk) OR metadata.updated_at < :new_ts"

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                delay = BASE_DELAY_SECONDS * (2 ** (attempt - 1))
                logger.info(
                    "Retrying conditional update for %s (attempt %d/%d, delay %.1fs)",
                    pk,
                    attempt,
                    self.max_retries,
                    delay,
                )
                time.sleep(delay)

            try:
                self._table.update_item(
                    Key={"pk": pk, "sk": sk},
                    UpdateExpression=update_expression,
                    ExpressionAttributeNames=expression_attribute_names,
                    ExpressionAttributeValues=expression_attribute_values,
                    ConditionExpression=condition_expression,
                )
                return True
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ConditionalCheckFailedException":
                    # Newer data already exists — this is expected behavior
                    logger.debug(
                        "Conditional write skipped for %s: newer data exists",
                        pk,
                    )
                    return True  # Not a failure; item is already up-to-date
                elif error_code in (
                    "ProvisionedThroughputExceededException",
                    "ThrottlingException",
                    "InternalServerError",
                ):
                    if attempt == self.max_retries:
                        logger.error(
                            "Conditional update failed for %s after %d retries: %s",
                            pk,
                            self.max_retries,
                            error_code,
                        )
                        return False
                    # Retryable — continue to next attempt
                    continue
                else:
                    # Non-retryable error
                    logger.error(
                        "Conditional update failed for %s: %s - %s",
                        pk,
                        error_code,
                        e.response["Error"]["Message"],
                    )
                    return False

        return False
