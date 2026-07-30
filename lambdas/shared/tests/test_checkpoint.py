"""Unit tests for the CheckpointManager module."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from lambdas.shared.checkpoint import CHECKPOINT_PK, Checkpoint, CheckpointManager
from lambdas.shared.exceptions import WriteError


@pytest.fixture
def mock_table():
    """Create a mock DynamoDB table resource."""
    with patch("lambdas.shared.checkpoint.boto3") as mock_boto3:
        mock_tbl = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_tbl
        yield mock_tbl


class TestCheckpointRead:
    """Tests for CheckpointManager.read()."""

    def test_read_returns_checkpoint_when_item_exists(self, mock_table):
        mock_table.get_item.return_value = {
            "Item": {
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": "2024-01-15T10:00:00Z",
                "meta_sha256": "a" * 64,
            }
        }

        mgr = CheckpointManager(table_name="test-table", source="NVD")
        result = mgr.read()

        assert result is not None
        assert isinstance(result, Checkpoint)
        assert result.last_successful_sync == "2024-01-15T10:00:00Z"
        assert result.meta_sha256 == "a" * 64

    def test_read_returns_none_when_no_item(self, mock_table):
        mock_table.get_item.return_value = {}

        mgr = CheckpointManager(table_name="test-table", source="NVD")
        result = mgr.read()

        assert result is None

    def test_read_returns_none_on_client_error(self, mock_table):
        mock_table.get_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "oops"}},
            "GetItem",
        )

        mgr = CheckpointManager(table_name="test-table", source="NVD")
        result = mgr.read()

        assert result is None

    def test_read_uses_consistent_read(self, mock_table):
        mock_table.get_item.return_value = {}

        mgr = CheckpointManager(table_name="test-table", source="NVD")
        mgr.read()

        mock_table.get_item.assert_called_once_with(
            Key={"pk": CHECKPOINT_PK, "sk": "NVD"},
            ConsistentRead=True,
        )

    def test_read_uses_correct_source_key(self, mock_table):
        mock_table.get_item.return_value = {}

        mgr = CheckpointManager(table_name="test-table", source="EPSS")
        mgr.read()

        mock_table.get_item.assert_called_once_with(
            Key={"pk": CHECKPOINT_PK, "sk": "EPSS"},
            ConsistentRead=True,
        )


class TestCheckpointWrite:
    """Tests for CheckpointManager.write()."""

    def test_write_puts_correct_item(self, mock_table):
        mgr = CheckpointManager(table_name="test-table", source="NVD")
        mgr.write(
            last_sync="2024-01-15T12:00:00Z",
            meta_sha256="b" * 64,
        )

        mock_table.put_item.assert_called_once_with(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "NVD",
                "last_successful_sync": "2024-01-15T12:00:00Z",
                "meta_sha256": "b" * 64,
            }
        )

    def test_write_raises_write_error_on_client_error(self, mock_table):
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "oops"}},
            "PutItem",
        )

        mgr = CheckpointManager(table_name="test-table", source="NVD")

        with pytest.raises(WriteError) as exc_info:
            mgr.write(
                last_sync="2024-01-15T12:00:00Z",
                meta_sha256="c" * 64,
            )

        assert exc_info.value.source == "NVD"
        assert exc_info.value.operation == "write_checkpoint"

    def test_write_uses_correct_source_key(self, mock_table):
        mgr = CheckpointManager(table_name="test-table", source="KEV")
        mgr.write(
            last_sync="2024-06-01T00:00:00Z",
            meta_sha256="d" * 64,
        )

        mock_table.put_item.assert_called_once_with(
            Item={
                "pk": CHECKPOINT_PK,
                "sk": "KEV",
                "last_successful_sync": "2024-06-01T00:00:00Z",
                "meta_sha256": "d" * 64,
            }
        )


class TestCheckpointDataclass:
    """Tests for the Checkpoint dataclass."""

    def test_checkpoint_is_frozen(self):
        cp = Checkpoint(
            last_successful_sync="2024-01-01T00:00:00Z",
            meta_sha256="e" * 64,
        )
        with pytest.raises(AttributeError):
            cp.last_successful_sync = "2025-01-01T00:00:00Z"  # type: ignore[misc]

    def test_checkpoint_equality(self):
        cp1 = Checkpoint(
            last_successful_sync="2024-01-01T00:00:00Z",
            meta_sha256="f" * 64,
        )
        cp2 = Checkpoint(
            last_successful_sync="2024-01-01T00:00:00Z",
            meta_sha256="f" * 64,
        )
        assert cp1 == cp2
