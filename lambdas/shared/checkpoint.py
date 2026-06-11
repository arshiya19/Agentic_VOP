"""Checkpoint management for per-source sync state.

Reads and writes sync checkpoint items in DynamoDB to track the last
successful sync timestamp and feed hash for each intelligence source.
The checkpoint is updated only after all batch writes for a sync run
have succeeded.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

from lambdas.shared.exceptions import WriteError

logger = logging.getLogger(__name__)

CHECKPOINT_PK = "SYSTEM#SYNC"


@dataclass(frozen=True)
class Checkpoint:
    """Immutable snapshot of a source's sync checkpoint."""

    last_successful_sync: str  # ISO 8601 UTC timestamp
    meta_sha256: str  # 64-char lowercase hex SHA-256


class CheckpointManager:
    """Manages per-source sync checkpoints in DynamoDB.

    Each source (e.g. "NVD") has a single checkpoint item keyed by
    pk=SYSTEM#SYNC, sk={source}. The checkpoint records the last
    successful sync timestamp and the META file hash to enable
    change detection and idempotent reprocessing.
    """

    def __init__(self, table_name: str, source: str) -> None:
        self._table_name = table_name
        self._source = source
        self._table = boto3.resource("dynamodb").Table(table_name)

    def read(self) -> Checkpoint | None:
        """Read current checkpoint for this source.

        Returns:
            A Checkpoint dataclass if a checkpoint item exists, or None
            if no checkpoint has been written yet.
        """
        try:
            response = self._table.get_item(
                Key={"pk": CHECKPOINT_PK, "sk": self._source},
                ConsistentRead=True,
            )
        except ClientError as exc:
            logger.error(
                "Failed to read checkpoint for source=%s: %s",
                self._source,
                exc,
            )
            return None

        item = response.get("Item")
        if item is None:
            logger.info("No checkpoint found for source=%s", self._source)
            return None

        return Checkpoint(
            last_successful_sync=item["last_successful_sync"],
            meta_sha256=item["meta_sha256"],
        )

    def write(self, last_sync: str, meta_sha256: str) -> None:
        """Update checkpoint. Only call after all writes succeed.

        Args:
            last_sync: ISO 8601 UTC timestamp of the latest successfully
                synced item.
            meta_sha256: 64-char lowercase hex SHA-256 of the META file.

        Raises:
            WriteError: If the DynamoDB put operation fails.
        """
        try:
            self._table.put_item(
                Item={
                    "pk": CHECKPOINT_PK,
                    "sk": self._source,
                    "last_successful_sync": last_sync,
                    "meta_sha256": meta_sha256,
                }
            )
        except ClientError as exc:
            raise WriteError(
                source=self._source,
                operation="write_checkpoint",
                message=f"Failed to update checkpoint: {exc}",
            ) from exc

        logger.info(
            "Checkpoint updated for source=%s: last_sync=%s, meta_sha256=%s",
            self._source,
            last_sync,
            meta_sha256[:16] + "...",
        )
