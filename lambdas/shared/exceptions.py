"""Custom exception hierarchy for the intelligence layer.

Each exception carries `source` (the feed origin, e.g. "NVD") and
`operation` (the action that failed, e.g. "download_feed") so that
error handlers and structured logs have consistent context.
"""


class IntelligenceError(Exception):
    """Base for all intelligence layer errors."""

    def __init__(self, source: str, operation: str, message: str):
        self.source = source
        self.operation = operation
        super().__init__(f"[{source}] {operation}: {message}")


class FeedDownloadError(IntelligenceError):
    """Feed file could not be downloaded or decompressed."""


class TransformError(IntelligenceError):
    """Input data could not be transformed to target schema."""


class WriteError(IntelligenceError):
    """DynamoDB write operation failed after retries."""
