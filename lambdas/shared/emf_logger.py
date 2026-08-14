"""Structured JSON logging with CloudWatch Embedded Metric Format (EMF) emission.

Emits structured log entries to stdout that CloudWatch automatically extracts
metrics from. Each log entry includes an `_aws` block for EMF metric extraction
under the namespace `Sisyfix/NvdSync` with an `Environment` dimension.

Supported log events:
    SYNC_STARTED, META_UNCHANGED, FEED_DOWNLOADED, ITEMS_FILTERED,
    BATCH_WRITTEN, SYNC_COMPLETED, SYNC_FAILED, GAP_RECOVERY

Supported log levels:
    INFO, WARN, ERROR, CRITICAL

Usage:
    logger = EmfLogger(environment="dev", invocation_id="abc-123")
    logger.info("SYNC_STARTED", "Starting NVD sync run")
    logger.emit_metric("ItemsWritten", 42, "Count")
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class LogLevel(StrEnum):
    """Supported log levels."""

    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogEvent(StrEnum):
    """Named structured log events emitted during sync operations."""

    SYNC_STARTED = "SYNC_STARTED"
    META_UNCHANGED = "META_UNCHANGED"
    FEED_DOWNLOADED = "FEED_DOWNLOADED"
    ITEMS_FILTERED = "ITEMS_FILTERED"
    BATCH_WRITTEN = "BATCH_WRITTEN"
    SYNC_COMPLETED = "SYNC_COMPLETED"
    SYNC_FAILED = "SYNC_FAILED"
    GAP_RECOVERY = "GAP_RECOVERY"


_NAMESPACE = "Sisyfix/NvdSync"
_DIMENSION_NAME = "Environment"


class EmfLogger:
    """Structured JSON logger with CloudWatch Embedded Metric Format support.

    Each log entry is a single-line JSON object printed to stdout. Entries
    that include metrics contain an `_aws` block so CloudWatch can extract
    custom metrics automatically.

    Args:
        environment: Deployment environment name (e.g. "dev", "prod").
            Falls back to the ``ENVIRONMENT`` env var if not provided.
        invocation_id: AWS Lambda request ID for correlating log entries.
            Falls back to the ``AWS_REQUEST_ID`` env var if not provided.
    """

    def __init__(
        self,
        environment: str | None = None,
        invocation_id: str | None = None,
    ) -> None:
        self.environment = environment or os.environ.get("ENVIRONMENT", "unknown")
        self.invocation_id = invocation_id or os.environ.get("AWS_REQUEST_ID", "local")
        self._start_time_ms: int = _now_ms()

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def info(self, event: str, message: str, **extra: Any) -> None:
        """Emit an INFO-level structured log entry."""
        self._log(LogLevel.INFO, event, message, extra)

    def warn(self, event: str, message: str, **extra: Any) -> None:
        """Emit a WARN-level structured log entry."""
        self._log(LogLevel.WARN, event, message, extra)

    # Alias for compatibility — ruff G010 prefers .warning() over .warn()
    warning = warn

    def error(self, event: str, message: str, **extra: Any) -> None:
        """Emit an ERROR-level structured log entry."""
        self._log(LogLevel.ERROR, event, message, extra)

    def critical(self, event: str, message: str, **extra: Any) -> None:
        """Emit a CRITICAL-level structured log entry."""
        self._log(LogLevel.CRITICAL, event, message, extra)

    # ------------------------------------------------------------------
    # Metric emission
    # ------------------------------------------------------------------

    def emit_metric(
        self,
        metric_name: str,
        value: float,
        unit: str = "Count",
        **extra: Any,
    ) -> None:
        """Emit a single CloudWatch metric via EMF.

        Args:
            metric_name: The metric name (e.g. "ItemsWritten").
            value: Numeric metric value.
            unit: CloudWatch unit (Count, Milliseconds, None, etc.).
            **extra: Additional fields to include in the log entry.
        """
        entry = self._base_entry(LogLevel.INFO, "METRIC", f"{metric_name}={value}")
        entry[metric_name] = value
        entry.update(extra)
        entry["_aws"] = self._aws_block(
            metrics=[{"Name": metric_name, "Unit": unit}],
        )
        self._write(entry)

    def emit_metrics(
        self,
        metrics: dict[str, int | float],
        units: dict[str, str] | None = None,
        **extra: Any,
    ) -> None:
        """Emit multiple CloudWatch metrics in a single EMF log entry.

        Args:
            metrics: Mapping of metric name to value.
            units: Optional mapping of metric name to CloudWatch unit.
                Defaults to "Count" for any metric not specified.
            **extra: Additional fields to include in the log entry.
        """
        units = units or {}
        entry = self._base_entry(LogLevel.INFO, "METRICS", "Batch metric emission")
        entry.update(extra)

        metric_definitions: list[dict[str, str]] = []
        for name, value in metrics.items():
            entry[name] = value
            metric_definitions.append(
                {
                    "Name": name,
                    "Unit": units.get(name, "Count"),
                }
            )

        entry["_aws"] = self._aws_block(metrics=metric_definitions)
        self._write(entry)

    def log_with_metric(
        self,
        level: LogLevel | str,
        event: str,
        message: str,
        metric_name: str,
        metric_value: float,
        unit: str = "Count",
        **extra: Any,
    ) -> None:
        """Emit a structured log entry that also contains an EMF metric.

        Useful for events like SYNC_COMPLETED where you want both a log
        record and a metric in the same entry.
        """
        if isinstance(level, str):
            level = LogLevel(level)

        entry = self._base_entry(level, event, message)
        entry[metric_name] = metric_value
        entry.update(extra)
        entry["_aws"] = self._aws_block(
            metrics=[{"Name": metric_name, "Unit": unit}],
        )
        self._write(entry)

    # ------------------------------------------------------------------
    # Summary helper
    # ------------------------------------------------------------------

    def log_sync_summary(
        self,
        status: str,
        sync_mode: str,
        items_processed: int,
        items_written: int,
        items_skipped: int,
        items_failed: int,
        duration_ms: int,
        **extra: Any,
    ) -> None:
        """Emit the end-of-sync summary log with embedded metrics.

        Satisfies Requirement 19.5: summary log with status, sync_mode,
        items_processed, items_written, items_skipped, items_failed, duration_ms.
        """
        level = LogLevel.INFO if status == "success" else LogLevel.ERROR
        event = LogEvent.SYNC_COMPLETED.value if status == "success" else LogEvent.SYNC_FAILED.value

        entry = self._base_entry(level, event, f"Sync {status}")
        entry.update(
            {
                "status": status,
                "sync_mode": sync_mode,
                "items_processed": items_processed,
                "items_written": items_written,
                "items_skipped": items_skipped,
                "items_failed": items_failed,
                "duration_ms": duration_ms,
                "ItemsWritten": items_written,
                "ItemsSkipped": items_skipped,
                "SyncDurationMs": duration_ms,
                "Errors": 1 if status == "failed" else 0,
            }
        )
        entry.update(extra)

        entry["_aws"] = self._aws_block(
            metrics=[
                {"Name": "ItemsWritten", "Unit": "Count"},
                {"Name": "ItemsSkipped", "Unit": "Count"},
                {"Name": "SyncDurationMs", "Unit": "Milliseconds"},
                {"Name": "Errors", "Unit": "Count"},
            ],
        )
        self._write(entry)

    # ------------------------------------------------------------------
    # Elapsed time helper
    # ------------------------------------------------------------------

    def elapsed_ms(self) -> int:
        """Return milliseconds elapsed since this logger was created."""
        return _now_ms() - self._start_time_ms

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, level: LogLevel, event: str, message: str, extra: dict[str, Any]) -> None:
        """Build and write a structured log entry (no EMF metrics)."""
        entry = self._base_entry(level, event, message)
        entry.update(extra)
        self._write(entry)

    def _base_entry(self, level: LogLevel, event: str, message: str) -> dict[str, Any]:
        """Create the base log entry dict with standard fields."""
        return {
            "timestamp": _iso_now(),
            "level": level.value if isinstance(level, LogLevel) else level,
            "event": event,
            "invocation_id": self.invocation_id,
            "message": message,
            "environment": self.environment,
            "duration_ms": self.elapsed_ms(),
        }

    def _aws_block(self, metrics: list[dict[str, str]]) -> dict[str, Any]:
        """Build the EMF `_aws` block for CloudWatch metric extraction."""
        return {
            "Timestamp": _now_ms(),
            "CloudWatchMetrics": [
                {
                    "Namespace": _NAMESPACE,
                    "Dimensions": [[_DIMENSION_NAME]],
                    "Metrics": metrics,
                }
            ],
        }

    def _write(self, entry: dict[str, Any]) -> None:
        """Serialize entry as single-line JSON to stdout."""
        print(json.dumps(entry, default=str), file=sys.stdout, flush=True)


# ------------------------------------------------------------------
# Module-level utilities
# ------------------------------------------------------------------


def _now_ms() -> int:
    """Current time as milliseconds since Unix epoch."""
    return int(time.time() * 1000)


def _iso_now() -> str:
    """Current time as ISO 8601 UTC string."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")
