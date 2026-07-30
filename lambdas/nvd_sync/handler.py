"""NVD Sync Lambda handler entry point.

Orchestrates the end-to-end NVD feed synchronization pipeline:
1. Read checkpoint from DynamoDB
2. Determine sync mode based on gap duration
3. For normal sync: fetch META → download feed → filter → transform → batch write → update checkpoint
4. Return structured SyncResponse on all paths (success, failure, early exit)

Emits CloudWatch EMF metrics and structured log events throughout execution.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import UTC, datetime

from lambdas.nvd_sync.config import (
    BATCH_SIZE,
    CRITICAL_GAP_DAYS,
    ENVIRONMENT,
    GAP_THRESHOLD_DAYS,
    NVD_MODIFIED_FEED_URL,
    NVD_MODIFIED_META_URL,
    TIMEOUT_SAFETY_BUFFER_MS,
    get_table_name,
)
from lambdas.nvd_sync.filters import filter_cves_by_checkpoint
from lambdas.nvd_sync.gap_recovery import recover_gap
from lambdas.nvd_sync.transformer import transform_nvd_cve
from lambdas.shared.checkpoint import CheckpointManager
from lambdas.shared.dynamo_writer import DynamoWriter
from lambdas.shared.emf_logger import EmfLogger
from lambdas.shared.exceptions import FeedDownloadError, TransformError, WriteError
from lambdas.shared.feed_ingestion import (
    download_and_decompress,
    fetch_meta_sha256,
    parse_json_feed,
)


@dataclass
class SyncResponse:
    """Structured response returned by every sync invocation."""

    status: str  # "success" | "failed"
    sync_mode: str  # "normal" | "gap_recovery" | "critical"
    items_processed: int
    items_written: int
    items_skipped: int
    items_failed: int
    new_checkpoint: str | None  # ISO 8601 or None on failure
    duration_ms: int


def lambda_handler(event: dict, context) -> dict:
    """Lambda entry point for NVD feed synchronization.

    Args:
        event: EventBridge scheduled event payload (unused).
        context: AWS Lambda context object providing invocation metadata.

    Returns:
        dict: Serialized SyncResponse with sync execution results.
    """
    invocation_id = getattr(context, "aws_request_id", "local")
    logger = EmfLogger(environment=ENVIRONMENT, invocation_id=invocation_id)
    timestamp = datetime.now(UTC).isoformat()

    table_name = get_table_name(ENVIRONMENT)
    checkpoint_mgr = CheckpointManager(table_name=table_name, source="NVD")
    writer = DynamoWriter(table_name=table_name)

    logger.info("SYNC_STARTED", "NVD sync invocation started", timestamp=timestamp)

    # ------------------------------------------------------------------
    # Step 1: Read checkpoint
    # ------------------------------------------------------------------
    checkpoint = checkpoint_mgr.read()
    last_sync_ts = checkpoint.last_successful_sync if checkpoint else None
    stored_meta_hash = checkpoint.meta_sha256 if checkpoint else None

    # ------------------------------------------------------------------
    # Step 2: Determine sync mode based on gap
    # ------------------------------------------------------------------
    sync_mode = _determine_sync_mode(last_sync_ts)

    # ------------------------------------------------------------------
    # Handle critical gap (≥120 days)
    # ------------------------------------------------------------------
    if sync_mode == "critical":
        logger.critical(
            "SYNC_FAILED",
            f"Gap exceeds {CRITICAL_GAP_DAYS} days. Manual re-backfill required.",
            sync_mode=sync_mode,
        )
        response = SyncResponse(
            status="failed",
            sync_mode="critical",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Handle gap recovery (8 ≤ gap < 120 days)
    # ------------------------------------------------------------------
    if sync_mode == "gap_recovery":
        return _gap_recovery_sync(
            context=context,
            logger=logger,
            checkpoint_mgr=checkpoint_mgr,
            writer=writer,
            last_sync_ts=last_sync_ts,
            timestamp=timestamp,
        )

    # ------------------------------------------------------------------
    # Normal sync path
    # ------------------------------------------------------------------
    return _normal_sync(
        context=context,
        logger=logger,
        checkpoint_mgr=checkpoint_mgr,
        writer=writer,
        last_sync_ts=last_sync_ts,
        stored_meta_hash=stored_meta_hash,
        timestamp=timestamp,
    )


def _normal_sync(
    *,
    context,
    logger: EmfLogger,
    checkpoint_mgr: CheckpointManager,
    writer: DynamoWriter,
    last_sync_ts: str | None,
    stored_meta_hash: str | None,
    timestamp: str,
) -> dict:
    """Execute the normal feed-based sync pipeline.

    Returns:
        dict: Serialized SyncResponse.
    """
    items_processed = 0
    items_written = 0
    items_skipped = 0
    items_failed = 0

    # ------------------------------------------------------------------
    # Step 3a: Fetch META file SHA-256
    # ------------------------------------------------------------------
    try:
        current_meta_hash = fetch_meta_sha256(NVD_MODIFIED_META_URL)
    except FeedDownloadError as exc:
        logger.error(
            "SYNC_FAILED",
            f"Failed to fetch META file: {exc}",
            sync_mode="normal",
        )
        response = SyncResponse(
            status="failed",
            sync_mode="normal",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Step 3b: Compare META hash → early exit if unchanged
    # ------------------------------------------------------------------
    if stored_meta_hash and current_meta_hash == stored_meta_hash:
        logger.info(
            "META_UNCHANGED",
            "META hash unchanged, skipping feed download",
            meta_sha256=current_meta_hash[:16] + "...",
        )
        logger.emit_metric("MetaUnchanged", 1, "Count")
        response = SyncResponse(
            status="success",
            sync_mode="normal",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=last_sync_ts,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Step 3c: Download and decompress modified feed
    # ------------------------------------------------------------------
    try:
        raw_data = download_and_decompress(NVD_MODIFIED_FEED_URL)
    except FeedDownloadError as exc:
        logger.error(
            "SYNC_FAILED",
            f"Failed to download feed: {exc}",
            sync_mode="normal",
        )
        response = SyncResponse(
            status="failed",
            sync_mode="normal",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Step 3d: Parse JSON feed (NVD 2.0 format: "vulnerabilities" key)
    # ------------------------------------------------------------------
    try:
        feed_data = parse_json_feed(raw_data)
    except FeedDownloadError as exc:
        logger.error(
            "SYNC_FAILED",
            f"Failed to parse feed JSON: {exc}",
            sync_mode="normal",
        )
        response = SyncResponse(
            status="failed",
            sync_mode="normal",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # Extract vulnerabilities array (NVD 2.0 format)
    cve_items = feed_data.get("vulnerabilities", [])

    logger.info(
        "FEED_DOWNLOADED",
        f"Feed downloaded and parsed: {len(cve_items)} total CVE items",
        total_items=len(cve_items),
    )

    # ------------------------------------------------------------------
    # Step 3e: Filter by checkpoint timestamp
    # ------------------------------------------------------------------
    filtered_items = filter_cves_by_checkpoint(cve_items, last_sync_ts)
    items_processed = len(filtered_items)

    logger.info(
        "ITEMS_FILTERED",
        f"Filtered to {items_processed} items newer than checkpoint",
        items_before=len(cve_items),
        items_after=items_processed,
        checkpoint=last_sync_ts,
    )

    if items_processed == 0:
        # No new items to process
        response = SyncResponse(
            status="success",
            sync_mode="normal",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=last_sync_ts,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Step 3f: Transform each CVE item
    # ------------------------------------------------------------------
    transformed_items: list[dict] = []
    max_last_modified: str | None = None

    for item in filtered_items:
        try:
            dynamo_item = transform_nvd_cve(item, timestamp)
            transformed_items.append(dynamo_item)

            # Track max lastModifiedDate for checkpoint update
            last_mod = _get_last_modified_from_item(item)
            if last_mod and (max_last_modified is None or last_mod > max_last_modified):
                max_last_modified = last_mod

        except TransformError as exc:
            items_skipped += 1
            cve_id = _extract_cve_id_for_logging(item)
            logger.warning(
                "SYNC_FAILED",
                f"Transform failed for {cve_id}: {exc}",
                cve_id=cve_id,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Step 3g: Batch write transformed items with timeout safety
    # ------------------------------------------------------------------
    batches = _partition_items(transformed_items, BATCH_SIZE)
    timed_out = False

    for batch in batches:
        # Check remaining execution time before each batch
        remaining_ms = context.get_remaining_time_in_millis()
        if remaining_ms < TIMEOUT_SAFETY_BUFFER_MS:
            logger.warning(
                "SYNC_FAILED",
                f"Timeout safety triggered: {remaining_ms}ms remaining, "
                f"need {TIMEOUT_SAFETY_BUFFER_MS}ms buffer",
                remaining_ms=remaining_ms,
                items_written_so_far=items_written,
                items_remaining=len(transformed_items) - items_written,
            )
            timed_out = True
            break

        try:
            result = writer.batch_put_items(batch)
            items_written += result.items_written
            items_failed += result.items_failed

            logger.info(
                "BATCH_WRITTEN",
                f"Batch written: {result.items_written} items",
                batch_written=result.items_written,
                batch_failed=result.items_failed,
                total_written=items_written,
            )
        except WriteError as exc:
            items_failed += len(batch)
            logger.error(
                "SYNC_FAILED",
                f"Batch write failed after retries: {exc}",
                sync_mode="normal",
                items_written=items_written,
                items_failed=items_failed,
            )
            # Abort on write failure — checkpoint unchanged
            response = SyncResponse(
                status="failed",
                sync_mode="normal",
                items_processed=items_processed,
                items_written=items_written,
                items_skipped=items_skipped,
                items_failed=items_failed,
                new_checkpoint=None,
                duration_ms=logger.elapsed_ms(),
            )
            logger.log_sync_summary(
                status=response.status,
                sync_mode=response.sync_mode,
                items_processed=response.items_processed,
                items_written=response.items_written,
                items_skipped=response.items_skipped,
                items_failed=response.items_failed,
                duration_ms=response.duration_ms,
            )
            return dataclasses.asdict(response)

    # Handle timeout — do NOT update checkpoint
    if timed_out:
        response = SyncResponse(
            status="failed",
            sync_mode="normal",
            items_processed=items_processed,
            items_written=items_written,
            items_skipped=items_skipped,
            items_failed=items_failed,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Step 3h: Update checkpoint to max lastModifiedDate of written items
    # ------------------------------------------------------------------
    new_checkpoint = max_last_modified or last_sync_ts

    if new_checkpoint and items_written > 0:
        try:
            checkpoint_mgr.write(
                last_sync=new_checkpoint,
                meta_sha256=current_meta_hash,
            )
        except WriteError as exc:
            logger.error(
                "SYNC_FAILED",
                f"Failed to update checkpoint: {exc}",
                sync_mode="normal",
            )
            response = SyncResponse(
                status="failed",
                sync_mode="normal",
                items_processed=items_processed,
                items_written=items_written,
                items_skipped=items_skipped,
                items_failed=items_failed,
                new_checkpoint=None,
                duration_ms=logger.elapsed_ms(),
            )
            logger.log_sync_summary(
                status=response.status,
                sync_mode=response.sync_mode,
                items_processed=response.items_processed,
                items_written=response.items_written,
                items_skipped=response.items_skipped,
                items_failed=response.items_failed,
                duration_ms=response.duration_ms,
            )
            return dataclasses.asdict(response)

    # ------------------------------------------------------------------
    # Success
    # ------------------------------------------------------------------
    logger.emit_metric("ItemsWritten", items_written, "Count")

    response = SyncResponse(
        status="success",
        sync_mode="normal",
        items_processed=items_processed,
        items_written=items_written,
        items_skipped=items_skipped,
        items_failed=items_failed,
        new_checkpoint=new_checkpoint,
        duration_ms=logger.elapsed_ms(),
    )
    logger.log_sync_summary(
        status=response.status,
        sync_mode=response.sync_mode,
        items_processed=response.items_processed,
        items_written=response.items_written,
        items_skipped=response.items_skipped,
        items_failed=response.items_failed,
        duration_ms=response.duration_ms,
    )
    return dataclasses.asdict(response)


def _gap_recovery_sync(
    *,
    context,
    logger: EmfLogger,
    checkpoint_mgr: CheckpointManager,
    writer: DynamoWriter,
    last_sync_ts: str | None,
    timestamp: str,
) -> dict:
    """Execute gap recovery via NVD API and write results through the normal pipeline.

    Returns:
        dict: Serialized SyncResponse.
    """
    items_processed = 0
    items_written = 0
    items_skipped = 0
    items_failed = 0

    # --- Invoke gap recovery module ---
    recovery_result = recover_gap(
        checkpoint_timestamp=last_sync_ts,
        environment=ENVIRONMENT,
        logger=logger,
        context=context,
    )

    if not recovery_result.success:
        response = SyncResponse(
            status="failed",
            sync_mode="gap_recovery",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    cve_items = recovery_result.cve_items
    items_processed = len(cve_items)

    if items_processed == 0:
        response = SyncResponse(
            status="success",
            sync_mode="gap_recovery",
            items_processed=0,
            items_written=0,
            items_skipped=0,
            items_failed=0,
            new_checkpoint=last_sync_ts,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # --- Transform each CVE item ---
    transformed_items: list[dict] = []
    max_last_modified: str | None = None

    for item in cve_items:
        try:
            dynamo_item = transform_nvd_cve(item, timestamp)
            transformed_items.append(dynamo_item)

            # Track max lastModifiedDate for checkpoint update
            last_mod = _get_last_modified_from_item(item)
            if last_mod and (max_last_modified is None or last_mod > max_last_modified):
                max_last_modified = last_mod

        except TransformError as exc:
            items_skipped += 1
            cve_id = _extract_cve_id_for_logging(item)
            logger.warning(
                "GAP_RECOVERY",
                f"Transform failed for {cve_id}: {exc}",
                cve_id=cve_id,
                error=str(exc),
            )

    # --- Batch write transformed items with timeout safety ---
    batches = _partition_items(transformed_items, BATCH_SIZE)
    timed_out = False

    for batch in batches:
        # Check remaining execution time before each batch
        remaining_ms = context.get_remaining_time_in_millis()
        if remaining_ms < TIMEOUT_SAFETY_BUFFER_MS:
            logger.warning(
                "GAP_RECOVERY",
                f"Timeout safety triggered: {remaining_ms}ms remaining, "
                f"need {TIMEOUT_SAFETY_BUFFER_MS}ms buffer",
                remaining_ms=remaining_ms,
                items_written_so_far=items_written,
                items_remaining=len(transformed_items) - items_written,
            )
            timed_out = True
            break

        try:
            result = writer.batch_put_items(batch)
            items_written += result.items_written
            items_failed += result.items_failed

            logger.info(
                "BATCH_WRITTEN",
                f"Gap recovery batch written: {result.items_written} items",
                batch_written=result.items_written,
                batch_failed=result.items_failed,
                total_written=items_written,
            )
        except WriteError as exc:
            items_failed += len(batch)
            logger.error(
                "GAP_RECOVERY",
                f"Batch write failed after retries: {exc}",
                sync_mode="gap_recovery",
                items_written=items_written,
                items_failed=items_failed,
            )
            # Abort on write failure — checkpoint unchanged
            response = SyncResponse(
                status="failed",
                sync_mode="gap_recovery",
                items_processed=items_processed,
                items_written=items_written,
                items_skipped=items_skipped,
                items_failed=items_failed,
                new_checkpoint=None,
                duration_ms=logger.elapsed_ms(),
            )
            logger.log_sync_summary(
                status=response.status,
                sync_mode=response.sync_mode,
                items_processed=response.items_processed,
                items_written=response.items_written,
                items_skipped=response.items_skipped,
                items_failed=response.items_failed,
                duration_ms=response.duration_ms,
            )
            return dataclasses.asdict(response)

    # Handle timeout — do NOT update checkpoint
    if timed_out:
        response = SyncResponse(
            status="failed",
            sync_mode="gap_recovery",
            items_processed=items_processed,
            items_written=items_written,
            items_skipped=items_skipped,
            items_failed=items_failed,
            new_checkpoint=None,
            duration_ms=logger.elapsed_ms(),
        )
        logger.log_sync_summary(
            status=response.status,
            sync_mode=response.sync_mode,
            items_processed=response.items_processed,
            items_written=response.items_written,
            items_skipped=response.items_skipped,
            items_failed=response.items_failed,
            duration_ms=response.duration_ms,
        )
        return dataclasses.asdict(response)

    # --- Update checkpoint on success ---
    new_checkpoint = max_last_modified or last_sync_ts

    if new_checkpoint and items_written > 0:
        try:
            # Use a placeholder hash for gap recovery (no META file involved)
            checkpoint_mgr.write(
                last_sync=new_checkpoint,
                meta_sha256="gap_recovery",
            )
        except WriteError as exc:
            logger.error(
                "GAP_RECOVERY",
                f"Failed to update checkpoint: {exc}",
                sync_mode="gap_recovery",
            )
            response = SyncResponse(
                status="failed",
                sync_mode="gap_recovery",
                items_processed=items_processed,
                items_written=items_written,
                items_skipped=items_skipped,
                items_failed=items_failed,
                new_checkpoint=None,
                duration_ms=logger.elapsed_ms(),
            )
            logger.log_sync_summary(
                status=response.status,
                sync_mode=response.sync_mode,
                items_processed=response.items_processed,
                items_written=response.items_written,
                items_skipped=response.items_skipped,
                items_failed=response.items_failed,
                duration_ms=response.duration_ms,
            )
            return dataclasses.asdict(response)

    # --- Success ---
    logger.emit_metric("ItemsWritten", items_written, "Count")

    response = SyncResponse(
        status="success",
        sync_mode="gap_recovery",
        items_processed=items_processed,
        items_written=items_written,
        items_skipped=items_skipped,
        items_failed=items_failed,
        new_checkpoint=new_checkpoint,
        duration_ms=logger.elapsed_ms(),
    )
    logger.log_sync_summary(
        status=response.status,
        sync_mode=response.sync_mode,
        items_processed=response.items_processed,
        items_written=response.items_written,
        items_skipped=response.items_skipped,
        items_failed=response.items_failed,
        duration_ms=response.duration_ms,
    )
    return dataclasses.asdict(response)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _determine_sync_mode(last_sync_ts: str | None) -> str:
    """Determine sync mode based on gap between now and last checkpoint.

    Args:
        last_sync_ts: ISO 8601 timestamp of last successful sync, or None
            if no checkpoint exists (first sync).

    Returns:
        "normal" if gap < 8 days (or first sync),
        "gap_recovery" if 8 ≤ gap < 120 days,
        "critical" if gap ≥ 120 days.
    """
    if last_sync_ts is None:
        # First sync — treat as normal (feed covers last 8 days)
        return "normal"

    try:
        last_sync_dt = datetime.fromisoformat(last_sync_ts)
        # Ensure timezone-aware comparison
        if last_sync_dt.tzinfo is None:
            last_sync_dt = last_sync_dt.replace(tzinfo=UTC)

        now = datetime.now(UTC)
        gap_days = (now - last_sync_dt).days

        if gap_days >= CRITICAL_GAP_DAYS:
            return "critical"
        elif gap_days >= GAP_THRESHOLD_DAYS:
            return "gap_recovery"
        else:
            return "normal"
    except (ValueError, TypeError):
        # If we can't parse the timestamp, treat as normal sync
        return "normal"


def _partition_items(items: list[dict], batch_size: int) -> list[list[dict]]:
    """Partition items into batches of the given size.

    Args:
        items: List of items to partition.
        batch_size: Maximum number of items per batch.

    Returns:
        List of batches, each containing at most batch_size items.
    """
    return [items[i : i + batch_size] for i in range(0, len(items), batch_size)]


def _get_last_modified_from_item(item: dict) -> str | None:
    """Extract lastModified timestamp from an NVD 2.0 CVE item.

    Args:
        item: NVD 2.0 CVE JSON object (the item from "vulnerabilities" array).

    Returns:
        The lastModified string or None if not found.
    """
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    last_modified = cve.get("lastModified")
    return last_modified if isinstance(last_modified, str) else None


def _extract_cve_id_for_logging(item: dict) -> str:
    """Extract CVE ID from item for logging purposes.

    Args:
        item: NVD 2.0 CVE JSON object.

    Returns:
        CVE ID string or "unknown" if extraction fails.
    """
    try:
        cve = item.get("cve", {})
        if isinstance(cve, dict):
            cve_id = cve.get("id")
            if isinstance(cve_id, str):
                return cve_id
    except (AttributeError, TypeError):
        pass
    return "unknown"
