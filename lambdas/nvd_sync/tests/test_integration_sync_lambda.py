"""Integration tests for the NVD Sync Lambda handler end-to-end.

Tests the full handler invocation with mocked HTTP (NVD feeds) and
moto-based DynamoDB. Covers normal sync, gap recovery trigger, and
critical gap abort paths.

Requirements: 2.1–2.13, 5.1–5.6, 7.1–7.7
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from lambdas.shared.checkpoint import CHECKPOINT_PK
from lambdas.shared.dynamo_writer import WriteResult

# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

TABLE_NAME = "sisyfix-dev-vulnerability-intelligence"
ENVIRONMENT = "dev"


def _make_nvd_cve_item(cve_id: str, last_modified: str) -> dict:
    """Create a minimal valid NVD 2.0 CVE JSON object."""
    return {
        "cve": {
            "id": cve_id,
            "lastModified": last_modified,
            "published": "2024-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
            "references": [],
            "weaknesses": [],
            "configurations": [],
            "metrics": {},
        }
    }


def _make_feed_json(cve_items: list[dict]) -> bytes:
    """Create a compressed NVD feed JSON payload."""
    feed = {"vulnerabilities": cve_items}
    return gzip.compress(json.dumps(feed).encode("utf-8"))


def _make_meta_content(sha256: str) -> str:
    """Create a META file content string."""
    return f"lastModifiedDate:2024-01-16T12:00:00-00:00\nsize:12345678\nsha256:{sha256}\n"


class FakeWriterBackedByTable:
    """A fake DynamoWriter that uses the moto Table resource for writes.

    The real DynamoWriter uses the low-level client API (batch_write_item)
    which requires DynamoDB typed attributes. For integration tests with moto,
    we use the Table resource (put_item) which accepts plain Python dicts.
    This validates the full pipeline except the wire format conversion.
    """

    def __init__(self, table):
        self._table = table
        self.table_name = table.table_name

    def batch_put_items(self, items: list[dict]) -> WriteResult:
        """Write items using Table resource put_item (accepts plain dicts)."""
        written = 0
        failed = 0
        for item in items:
            try:
                self._table.put_item(Item=item)
                written += 1
            except Exception:
                failed += 1
        return WriteResult(items_written=written, items_failed=failed)


@dataclass
class FakeLambdaContext:
    """Fake Lambda context for testing."""

    aws_request_id: str = "test-request-id-12345"
    _remaining_ms: int = 300_000  # 5 minutes

    def get_remaining_time_in_millis(self) -> int:
        return self._remaining_ms


@pytest.fixture
def aws_environment():
    """Set up moto-mocked AWS environment with DynamoDB table."""
    with mock_aws():
        # Create DynamoDB table
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield dynamodb


@pytest.fixture
def context():
    """Create a fake Lambda context with ample time remaining."""
    return FakeLambdaContext()


@pytest.fixture
def env_vars(monkeypatch):
    """Set environment variables for the Sync Lambda."""
    monkeypatch.setenv("ENVIRONMENT", ENVIRONMENT)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Normal sync tests
# ---------------------------------------------------------------------------


class TestNormalSyncEndToEnd:
    """Integration tests for the normal sync path."""

    def test_normal_sync_full_flow_writes_items_and_updates_checkpoint(
        self, aws_environment, context, env_vars
    ):
        """Test end-to-end normal sync: feed download → filter → transform → write → checkpoint."""
        now = datetime.now(UTC)
        checkpoint_ts = (now - timedelta(hours=4)).isoformat()
        new_meta_hash = "a" * 64
        old_meta_hash = "b" * 64

        # Seed checkpoint
        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": old_meta_hash,
            }
        )

        # Create feed with 3 CVEs newer than checkpoint
        newer_ts = (now - timedelta(hours=1)).isoformat()
        cve_items = [_make_nvd_cve_item(f"CVE-2024-{i:04d}", newer_ts) for i in range(1, 4)]
        feed_data = _make_feed_json(cve_items)
        meta_content = _make_meta_content(new_meta_hash)

        fake_writer = FakeWriterBackedByTable(table)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.nvd_sync.handler.DynamoWriter", return_value=fake_writer),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            # Mock META file response
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            # Mock feed download response
            mock_feed_response = MagicMock()
            mock_feed_response.status = 200
            mock_feed_response.read.return_value = feed_data

            # urlopen called twice: first for META, then for feed
            mock_urlopen.side_effect = [mock_meta_response, mock_feed_response]

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "success"
        assert result["sync_mode"] == "normal"
        assert result["items_written"] == 3
        assert result["items_skipped"] == 0
        assert result["items_failed"] == 0
        assert result["new_checkpoint"] is not None

        # Verify items written to DynamoDB
        for i in range(1, 4):
            resp = table.get_item(Key={"pk": f"CVE#CVE-2024-{i:04d}", "sk": "INTEL"})
            assert "Item" in resp
            assert resp["Item"]["cve_id"] == f"CVE-2024-{i:04d}"
            assert resp["Item"]["resolution"] == "resolved"

        # Verify checkpoint updated
        cp_resp = table.get_item(Key={"pk": CHECKPOINT_PK, "sk": "NVD"})
        assert cp_resp["Item"]["meta_sha256"] == new_meta_hash
        assert cp_resp["Item"]["last_successful_sync"] != checkpoint_ts

    def test_meta_unchanged_exits_early(self, aws_environment, context, env_vars):
        """Test that identical META hash triggers early exit without feed download."""
        now = datetime.now(UTC)
        checkpoint_ts = (now - timedelta(hours=1)).isoformat()
        same_hash = "c" * 64

        # Seed checkpoint with same hash
        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": same_hash,
            }
        )

        meta_content = _make_meta_content(same_hash)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            mock_urlopen.return_value = mock_meta_response

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "success"
        assert result["sync_mode"] == "normal"
        assert result["items_processed"] == 0
        assert result["items_written"] == 0
        # Feed was never downloaded (urlopen called only once for META)
        assert mock_urlopen.call_count == 1

    def test_empty_feed_returns_success_with_zero_items(self, aws_environment, context, env_vars):
        """Test that a feed with no CVEs newer than checkpoint produces success with 0 items."""
        now = datetime.now(UTC)
        # Checkpoint is very recent, so all items in feed will be older
        checkpoint_ts = now.isoformat()
        old_hash = "d" * 64
        new_hash = "e" * 64

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": old_hash,
            }
        )

        # Create feed with items older than checkpoint
        old_ts = (now - timedelta(hours=5)).isoformat()
        cve_items = [_make_nvd_cve_item("CVE-2024-9999", old_ts)]
        feed_data = _make_feed_json(cve_items)
        meta_content = _make_meta_content(new_hash)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            mock_feed_response = MagicMock()
            mock_feed_response.status = 200
            mock_feed_response.read.return_value = feed_data

            mock_urlopen.side_effect = [mock_meta_response, mock_feed_response]

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "success"
        assert result["items_processed"] == 0
        assert result["items_written"] == 0

    def test_first_sync_no_checkpoint_processes_all_items(self, aws_environment, context, env_vars):
        """Test first sync with no existing checkpoint processes all feed items."""
        new_hash = "f" * 64

        # No checkpoint seeded — first sync
        now = datetime.now(UTC)
        recent_ts = (now - timedelta(hours=2)).isoformat()
        cve_items = [
            _make_nvd_cve_item("CVE-2024-0001", recent_ts),
            _make_nvd_cve_item("CVE-2024-0002", recent_ts),
        ]
        feed_data = _make_feed_json(cve_items)
        meta_content = _make_meta_content(new_hash)

        table = aws_environment.Table(TABLE_NAME)
        fake_writer = FakeWriterBackedByTable(table)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.nvd_sync.handler.DynamoWriter", return_value=fake_writer),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            mock_feed_response = MagicMock()
            mock_feed_response.status = 200
            mock_feed_response.read.return_value = feed_data

            mock_urlopen.side_effect = [mock_meta_response, mock_feed_response]

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "success"
        assert result["items_written"] == 2

        # Verify checkpoint was created
        cp_resp = table.get_item(Key={"pk": CHECKPOINT_PK, "sk": "NVD"})
        assert "Item" in cp_resp
        assert cp_resp["Item"]["meta_sha256"] == new_hash


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


class TestSyncErrorHandling:
    """Integration tests for error handling paths."""

    def test_feed_download_failure_returns_failed_checkpoint_unchanged(
        self, aws_environment, context, env_vars
    ):
        """Test that feed download failure aborts run and leaves checkpoint unchanged."""
        now = datetime.now(UTC)
        checkpoint_ts = (now - timedelta(hours=2)).isoformat()
        old_hash = "a" * 64
        new_hash = "b" * 64

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": old_hash,
            }
        )

        meta_content = _make_meta_content(new_hash)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            # META succeeds
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            # Feed download fails
            from urllib.error import URLError

            mock_urlopen.side_effect = [
                mock_meta_response,
                URLError("Connection refused"),
            ]

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "failed"
        assert result["new_checkpoint"] is None

        # Verify checkpoint unchanged
        cp_resp = table.get_item(Key={"pk": CHECKPOINT_PK, "sk": "NVD"})
        assert cp_resp["Item"]["last_successful_sync"] == checkpoint_ts
        assert cp_resp["Item"]["meta_sha256"] == old_hash

    def test_timeout_safety_buffer_prevents_processing(self, aws_environment, env_vars):
        """Test that timeout safety buffer stops processing and leaves checkpoint unchanged."""
        now = datetime.now(UTC)
        checkpoint_ts = (now - timedelta(hours=2)).isoformat()
        old_hash = "a" * 64
        new_hash = "b" * 64

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": old_hash,
            }
        )

        # Create feed with items
        newer_ts = (now - timedelta(hours=1)).isoformat()
        cve_items = [_make_nvd_cve_item(f"CVE-2024-{i:04d}", newer_ts) for i in range(1, 30)]
        feed_data = _make_feed_json(cve_items)
        meta_content = _make_meta_content(new_hash)

        # Context with very little time remaining
        timeout_context = FakeLambdaContext(_remaining_ms=20_000)  # 20s < 30s buffer

        fake_writer = FakeWriterBackedByTable(table)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.nvd_sync.handler.DynamoWriter", return_value=fake_writer),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            mock_feed_response = MagicMock()
            mock_feed_response.status = 200
            mock_feed_response.read.return_value = feed_data

            mock_urlopen.side_effect = [mock_meta_response, mock_feed_response]

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, timeout_context)

        assert result["status"] == "failed"
        assert result["items_written"] == 0
        assert result["new_checkpoint"] is None

        # Checkpoint unchanged
        cp_resp = table.get_item(Key={"pk": CHECKPOINT_PK, "sk": "NVD"})
        assert cp_resp["Item"]["last_successful_sync"] == checkpoint_ts

    def test_malformed_cve_item_skipped_others_written(self, aws_environment, context, env_vars):
        """Test that malformed CVE items are skipped while valid items are still written."""
        now = datetime.now(UTC)
        checkpoint_ts = (now - timedelta(hours=4)).isoformat()
        old_hash = "x" * 64
        new_hash = "y" * 64

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": old_hash,
            }
        )

        newer_ts = (now - timedelta(hours=1)).isoformat()
        # One valid, one malformed (missing cve.id), one valid
        cve_items = [
            _make_nvd_cve_item("CVE-2024-0001", newer_ts),
            {"cve": {"lastModified": newer_ts}},  # Missing 'id' field
            _make_nvd_cve_item("CVE-2024-0003", newer_ts),
        ]
        feed_data = _make_feed_json(cve_items)
        meta_content = _make_meta_content(new_hash)

        fake_writer = FakeWriterBackedByTable(table)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.nvd_sync.handler.DynamoWriter", return_value=fake_writer),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")

            mock_feed_response = MagicMock()
            mock_feed_response.status = 200
            mock_feed_response.read.return_value = feed_data

            mock_urlopen.side_effect = [mock_meta_response, mock_feed_response]

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "success"
        assert result["items_written"] == 2
        assert result["items_skipped"] == 1

        # Verify valid items written
        resp1 = table.get_item(Key={"pk": "CVE#CVE-2024-0001", "sk": "INTEL"})
        assert "Item" in resp1
        resp3 = table.get_item(Key={"pk": "CVE#CVE-2024-0003", "sk": "INTEL"})
        assert "Item" in resp3


# ---------------------------------------------------------------------------
# Gap recovery and critical gap tests
# ---------------------------------------------------------------------------


class TestGapRecoveryIntegration:
    """Integration tests for gap recovery and critical gap paths."""

    def test_critical_gap_aborts_without_processing(self, aws_environment, context, env_vars):
        """Test that a gap >120 days triggers critical abort without recovery."""
        now = datetime.now(UTC)
        # Checkpoint is 150 days old
        old_checkpoint = (now - timedelta(days=150)).isoformat()

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": old_checkpoint,
                "meta_sha256": "z" * 64,
            }
        )

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
        ):
            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "failed"
        assert result["sync_mode"] == "critical"
        assert result["items_processed"] == 0
        assert result["new_checkpoint"] is None

        # Checkpoint unchanged
        cp_resp = table.get_item(Key={"pk": CHECKPOINT_PK, "sk": "NVD"})
        assert cp_resp["Item"]["last_successful_sync"] == old_checkpoint

    def test_gap_recovery_triggers_when_gap_between_8_and_120_days(
        self, aws_environment, context, env_vars
    ):
        """Test that gap recovery is triggered for gaps between 8 and 120 days."""
        now = datetime.now(UTC)
        # Checkpoint is 15 days old (between 8 and 120)
        old_checkpoint = (now - timedelta(days=15)).isoformat()

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": old_checkpoint,
                "meta_sha256": "g" * 64,
            }
        )

        # Mock gap recovery module to return some CVE items
        newer_ts = (now - timedelta(hours=1)).isoformat()
        mock_cve_items = [
            _make_nvd_cve_item("CVE-2024-5001", newer_ts),
            _make_nvd_cve_item("CVE-2024-5002", newer_ts),
        ]

        from lambdas.nvd_sync.gap_recovery import GapRecoveryResult

        mock_result = GapRecoveryResult(
            success=True,
            cve_items=mock_cve_items,
            total_retrieved=2,
        )

        fake_writer = FakeWriterBackedByTable(table)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.nvd_sync.handler.DynamoWriter", return_value=fake_writer),
            patch("lambdas.nvd_sync.handler.recover_gap", return_value=mock_result),
        ):
            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "success"
        assert result["sync_mode"] == "gap_recovery"
        assert result["items_written"] == 2

        # Verify items in DynamoDB
        resp = table.get_item(Key={"pk": "CVE#CVE-2024-5001", "sk": "INTEL"})
        assert "Item" in resp
        assert resp["Item"]["resolution"] == "resolved"

    def test_gap_recovery_failure_leaves_checkpoint_unchanged(
        self, aws_environment, context, env_vars
    ):
        """Test that failed gap recovery does not update checkpoint."""
        now = datetime.now(UTC)
        old_checkpoint = (now - timedelta(days=15)).isoformat()

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": old_checkpoint,
                "meta_sha256": "h" * 64,
            }
        )

        from lambdas.nvd_sync.gap_recovery import GapRecoveryResult

        mock_result = GapRecoveryResult(
            success=False,
            error_message="NVD API request failed after all retries.",
        )

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.nvd_sync.handler.recover_gap", return_value=mock_result),
        ):
            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        assert result["status"] == "failed"
        assert result["sync_mode"] == "gap_recovery"
        assert result["new_checkpoint"] is None

        # Checkpoint unchanged
        cp_resp = table.get_item(Key={"pk": CHECKPOINT_PK, "sk": "NVD"})
        assert cp_resp["Item"]["last_successful_sync"] == old_checkpoint


# ---------------------------------------------------------------------------
# Response structure tests
# ---------------------------------------------------------------------------


class TestSyncResponseStructure:
    """Tests that every execution path returns a complete SyncResponse."""

    REQUIRED_FIELDS = [
        "status",
        "sync_mode",
        "items_processed",
        "items_written",
        "items_skipped",
        "items_failed",
        "new_checkpoint",
        "duration_ms",
    ]

    def test_success_response_has_all_fields(self, aws_environment, context, env_vars):
        """Verify successful sync response contains all required fields."""
        now = datetime.now(UTC)
        checkpoint_ts = (now - timedelta(hours=2)).isoformat()
        same_hash = "r" * 64

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": checkpoint_ts,
                "meta_sha256": same_hash,
            }
        )

        meta_content = _make_meta_content(same_hash)

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
            patch("lambdas.shared.feed_ingestion.urlopen") as mock_urlopen,
        ):
            mock_meta_response = MagicMock()
            mock_meta_response.status = 200
            mock_meta_response.read.return_value = meta_content.encode("utf-8")
            mock_urlopen.return_value = mock_meta_response

            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        for field in self.REQUIRED_FIELDS:
            assert field in result, f"Missing field: {field}"

    def test_failed_response_has_all_fields(self, aws_environment, context, env_vars):
        """Verify failed sync response contains all required fields."""
        now = datetime.now(UTC)
        old_checkpoint = (now - timedelta(days=150)).isoformat()

        table = aws_environment.Table(TABLE_NAME)
        table.put_item(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": old_checkpoint,
                "meta_sha256": "s" * 64,
            }
        )

        with (
            patch("lambdas.nvd_sync.config.ENVIRONMENT", ENVIRONMENT),
            patch("lambdas.nvd_sync.config.get_table_name", return_value=TABLE_NAME),
        ):
            from lambdas.nvd_sync.handler import lambda_handler

            result = lambda_handler({}, context)

        for field in self.REQUIRED_FIELDS:
            assert field in result, f"Missing field: {field}"

        assert result["status"] == "failed"
        assert isinstance(result["duration_ms"], int)
        assert result["duration_ms"] >= 0
