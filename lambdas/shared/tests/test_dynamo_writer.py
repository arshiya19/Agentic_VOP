"""Unit tests for the DynamoWriter module."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from lambdas.shared.dynamo_writer import DynamoWriter, WriteResult, BATCH_SIZE
from lambdas.shared.exceptions import WriteError


@pytest.fixture
def mock_boto3():
    """Patch boto3 client and resource for DynamoWriter."""
    with patch("lambdas.shared.dynamo_writer.boto3") as mock_b3:
        mock_client = MagicMock()
        mock_resource = MagicMock()
        mock_table = MagicMock()

        mock_b3.client.return_value = mock_client
        mock_b3.resource.return_value = mock_resource
        mock_resource.Table.return_value = mock_table

        yield {
            "boto3": mock_b3,
            "client": mock_client,
            "resource": mock_resource,
            "table": mock_table,
        }


@pytest.fixture
def writer(mock_boto3):
    """Create a DynamoWriter with mocked boto3."""
    return DynamoWriter(table_name="test-table", max_retries=3)


class TestWriteResult:
    """Tests for the WriteResult dataclass."""

    def test_defaults(self):
        result = WriteResult()
        assert result.items_written == 0
        assert result.items_failed == 0
        assert result.unprocessed_items == []

    def test_custom_values(self):
        result = WriteResult(
            items_written=5, items_failed=2, unprocessed_items=[{"pk": "x"}]
        )
        assert result.items_written == 5
        assert result.items_failed == 2
        assert result.unprocessed_items == [{"pk": "x"}]


class TestBatchPutItems:
    """Tests for DynamoWriter.batch_put_items()."""

    def test_empty_items_returns_empty_result(self, writer):
        result = writer.batch_put_items([])
        assert result.items_written == 0
        assert result.items_failed == 0
        assert result.unprocessed_items == []

    def test_single_item_writes_successfully(self, writer, mock_boto3):
        items = [{"pk": "CVE#CVE-2024-0001", "sk": "INTEL", "cve_id": "CVE-2024-0001"}]
        result = writer.batch_put_items(items)

        assert result.items_written == 1
        assert result.items_failed == 0
        assert result.unprocessed_items == []

    def test_exactly_25_items_in_single_batch(self, writer, mock_boto3):
        items = [{"pk": f"CVE#CVE-2024-{i:04d}", "sk": "INTEL"} for i in range(25)]
        result = writer.batch_put_items(items)

        assert result.items_written == 25
        assert result.items_failed == 0

    def test_26_items_split_into_two_batches(self, writer, mock_boto3):
        items = [{"pk": f"CVE#CVE-2024-{i:04d}", "sk": "INTEL"} for i in range(26)]
        result = writer.batch_put_items(items)

        assert result.items_written == 26
        assert result.items_failed == 0

    def test_50_items_split_into_two_batches(self, writer, mock_boto3):
        items = [{"pk": f"CVE#CVE-2024-{i:04d}", "sk": "INTEL"} for i in range(50)]
        result = writer.batch_put_items(items)

        assert result.items_written == 50
        assert result.items_failed == 0

    @patch("lambdas.shared.dynamo_writer.time.sleep")
    def test_retries_on_client_error(self, mock_sleep, writer, mock_boto3):
        # First call raises ClientError, second succeeds
        call_count = {"n": 0}

        def side_effect_enter():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "oops"}},
                    "BatchWriteItem",
                )
            return MagicMock()

        mock_boto3["table"].batch_writer.return_value.__enter__ = lambda self: (
            side_effect_enter()
        )
        mock_boto3["table"].batch_writer.return_value.__exit__ = lambda self, *args: (
            None
        )

        items = [{"pk": "CVE#CVE-2024-0001", "sk": "INTEL"}]
        result = writer.batch_put_items(items)

        assert result.items_written == 1
        assert result.items_failed == 0
        mock_sleep.assert_called_once_with(1)

    @patch("lambdas.shared.dynamo_writer.time.sleep")
    def test_raises_write_error_when_retries_exhausted(
        self, mock_sleep, writer, mock_boto3
    ):
        # All attempts raise ClientError
        mock_boto3["table"].batch_writer.return_value.__enter__ = MagicMock(
            side_effect=ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "oops"}},
                "BatchWriteItem",
            )
        )
        mock_boto3["table"].batch_writer.return_value.__exit__ = lambda self, *args: (
            None
        )

        item = {"pk": "CVE#CVE-2024-0001", "sk": "INTEL"}
        with pytest.raises(WriteError) as exc_info:
            writer.batch_put_items([item])

        assert exc_info.value.source == "DynamoDB"
        assert exc_info.value.operation == "batch_put_items"
        assert "unprocessed items" in str(exc_info.value)

    @patch("lambdas.shared.dynamo_writer.time.sleep")
    def test_client_error_retries_then_fails(self, mock_sleep, writer, mock_boto3):
        mock_boto3["table"].batch_writer.return_value.__enter__ = MagicMock(
            side_effect=ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "oops"}},
                "BatchWriteItem",
            )
        )
        mock_boto3["table"].batch_writer.return_value.__exit__ = lambda self, *args: (
            None
        )

        item = {"pk": "CVE#CVE-2024-0001", "sk": "INTEL"}
        with pytest.raises(WriteError):
            writer.batch_put_items([item])


class TestBatchUpdateSource:
    """Tests for DynamoWriter.batch_update_source()."""

    def test_empty_updates_returns_empty_result(self, writer):
        result = writer.batch_update_source([], source="nvd")
        assert result.items_written == 0
        assert result.items_failed == 0

    def test_successful_update(self, writer, mock_boto3):
        mock_boto3["table"].update_item.return_value = {}

        updates = [
            {
                "pk": "CVE#CVE-2024-0001",
                "sk": "INTEL",
                "data": {"cvss_score": 7.5},
                "updated_at": "2024-06-01T00:00:00Z",
            }
        ]
        result = writer.batch_update_source(updates, source="nvd")

        assert result.items_written == 1
        assert result.items_failed == 0
        mock_boto3["table"].update_item.assert_called_once()

    def test_conditional_check_failed_counts_as_success(self, writer, mock_boto3):
        """ConditionalCheckFailedException means newer data exists; not a failure."""
        mock_boto3["table"].update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "cond"}},
            "UpdateItem",
        )

        updates = [
            {
                "pk": "CVE#CVE-2024-0001",
                "sk": "INTEL",
                "data": {"cvss_score": 7.5},
                "updated_at": "2024-01-01T00:00:00Z",
            }
        ]
        result = writer.batch_update_source(updates, source="nvd")

        assert result.items_written == 1
        assert result.items_failed == 0

    @patch("lambdas.shared.dynamo_writer.time.sleep")
    def test_throttle_retries_then_fails(self, mock_sleep, writer, mock_boto3):
        mock_boto3["table"].update_item.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ProvisionedThroughputExceededException",
                    "Message": "throttled",
                }
            },
            "UpdateItem",
        )

        updates = [
            {
                "pk": "CVE#CVE-2024-0001",
                "sk": "INTEL",
                "data": {"cvss_score": 7.5},
                "updated_at": "2024-06-01T00:00:00Z",
            }
        ]

        with pytest.raises(WriteError) as exc_info:
            writer.batch_update_source(updates, source="nvd")

        assert exc_info.value.source == "DynamoDB"
        assert exc_info.value.operation == "batch_update_source"

    def test_non_retryable_error_fails_immediately(self, writer, mock_boto3):
        mock_boto3["table"].update_item.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "bad request"}},
            "UpdateItem",
        )

        updates = [
            {
                "pk": "CVE#CVE-2024-0001",
                "sk": "INTEL",
                "data": {"cvss_score": 7.5},
                "updated_at": "2024-06-01T00:00:00Z",
            }
        ]

        with pytest.raises(WriteError):
            writer.batch_update_source(updates, source="nvd")

        # Only called once (no retries for non-retryable errors)
        assert mock_boto3["table"].update_item.call_count == 1

    def test_multiple_updates_mixed_results(self, writer, mock_boto3):
        """Test with one success and one non-retryable failure."""
        mock_boto3["table"].update_item.side_effect = [
            {},  # First update succeeds
            ClientError(
                {"Error": {"Code": "ValidationException", "Message": "bad"}},
                "UpdateItem",
            ),
        ]

        updates = [
            {
                "pk": "CVE#CVE-2024-0001",
                "sk": "INTEL",
                "data": {"cvss_score": 7.5},
                "updated_at": "2024-06-01T00:00:00Z",
            },
            {
                "pk": "CVE#CVE-2024-0002",
                "sk": "INTEL",
                "data": {"cvss_score": 9.0},
                "updated_at": "2024-06-01T00:00:00Z",
            },
        ]

        with pytest.raises(WriteError):
            writer.batch_update_source(updates, source="nvd")


class TestPartitioning:
    """Tests for the internal _partition method."""

    def test_empty_list(self, writer):
        result = writer._partition([])
        assert result == []

    def test_fewer_than_batch_size(self, writer):
        items = [{"pk": f"item-{i}"} for i in range(10)]
        result = writer._partition(items)
        assert len(result) == 1
        assert len(result[0]) == 10

    def test_exactly_batch_size(self, writer):
        items = [{"pk": f"item-{i}"} for i in range(BATCH_SIZE)]
        result = writer._partition(items)
        assert len(result) == 1
        assert len(result[0]) == BATCH_SIZE

    def test_one_more_than_batch_size(self, writer):
        items = [{"pk": f"item-{i}"} for i in range(BATCH_SIZE + 1)]
        result = writer._partition(items)
        assert len(result) == 2
        assert len(result[0]) == BATCH_SIZE
        assert len(result[1]) == 1

    def test_multiple_full_batches(self, writer):
        items = [{"pk": f"item-{i}"} for i in range(75)]
        result = writer._partition(items)
        assert len(result) == 3
        assert all(len(batch) == BATCH_SIZE for batch in result)

    def test_no_items_lost(self, writer):
        items = [{"pk": f"item-{i}"} for i in range(63)]
        result = writer._partition(items)
        flat = [item for batch in result for item in batch]
        assert flat == items
