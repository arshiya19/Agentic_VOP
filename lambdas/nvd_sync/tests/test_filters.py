"""Unit tests for the CVE filter module."""

from lambdas.nvd_sync.filters import filter_cves_by_checkpoint


def _make_cve_item(cve_id: str, last_modified: str | None = None) -> dict:
    """Helper to build a minimal NVD 2.0 CVE item for testing."""
    cve: dict = {"id": cve_id}
    if last_modified is not None:
        cve["lastModified"] = last_modified
    return {"cve": cve}


class TestFilterCvesByCheckpoint:
    """Tests for filter_cves_by_checkpoint."""

    def test_returns_all_items_when_checkpoint_is_none(self):
        items = [
            _make_cve_item("CVE-2024-0001", "2024-01-10T00:00:00.000"),
            _make_cve_item("CVE-2024-0002", "2024-01-11T00:00:00.000"),
        ]
        result = filter_cves_by_checkpoint(items, None)
        assert result == items

    def test_returns_empty_list_for_empty_input(self):
        result = filter_cves_by_checkpoint([], "2024-01-01T00:00:00.000")
        assert result == []

    def test_returns_empty_list_when_no_items_newer_than_checkpoint(self):
        items = [
            _make_cve_item("CVE-2024-0001", "2024-01-05T00:00:00.000"),
            _make_cve_item("CVE-2024-0002", "2024-01-06T00:00:00.000"),
        ]
        result = filter_cves_by_checkpoint(items, "2024-01-10T00:00:00.000")
        assert result == []

    def test_returns_only_items_strictly_after_checkpoint(self):
        items = [
            _make_cve_item("CVE-2024-0001", "2024-01-09T00:00:00.000"),
            _make_cve_item("CVE-2024-0002", "2024-01-10T00:00:00.000"),
            _make_cve_item("CVE-2024-0003", "2024-01-11T00:00:00.000"),
        ]
        # Checkpoint is exactly equal to the second item — it should NOT be included.
        result = filter_cves_by_checkpoint(items, "2024-01-10T00:00:00.000")
        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2024-0003"

    def test_skips_items_with_missing_last_modified(self):
        items = [
            _make_cve_item("CVE-2024-0001", "2024-01-15T00:00:00.000"),
            _make_cve_item("CVE-2024-0002"),  # Missing lastModified
        ]
        result = filter_cves_by_checkpoint(items, "2024-01-01T00:00:00.000")
        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2024-0001"

    def test_skips_items_with_missing_last_modified_when_checkpoint_is_none(self):
        items = [
            _make_cve_item("CVE-2024-0001", "2024-01-15T00:00:00.000"),
            _make_cve_item("CVE-2024-0002"),  # Missing lastModified
        ]
        result = filter_cves_by_checkpoint(items, None)
        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2024-0001"

    def test_skips_items_with_invalid_cve_structure(self):
        items = [
            {"not_cve": {"id": "CVE-2024-0001"}},  # No 'cve' key
            {"cve": "invalid"},  # 'cve' is not a dict
            _make_cve_item("CVE-2024-0003", "2024-01-20T00:00:00.000"),
        ]
        result = filter_cves_by_checkpoint(items, "2024-01-01T00:00:00.000")
        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2024-0003"

    def test_skips_items_with_non_string_last_modified(self):
        items = [
            {"cve": {"id": "CVE-2024-0001", "lastModified": 12345}},
            _make_cve_item("CVE-2024-0002", "2024-01-20T00:00:00.000"),
        ]
        result = filter_cves_by_checkpoint(items, "2024-01-01T00:00:00.000")
        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2024-0002"

    def test_preserves_order_of_filtered_items(self):
        items = [
            _make_cve_item("CVE-2024-0003", "2024-01-20T00:00:00.000"),
            _make_cve_item("CVE-2024-0001", "2024-01-05T00:00:00.000"),
            _make_cve_item("CVE-2024-0002", "2024-01-15T00:00:00.000"),
        ]
        result = filter_cves_by_checkpoint(items, "2024-01-10T00:00:00.000")
        assert len(result) == 2
        assert result[0]["cve"]["id"] == "CVE-2024-0003"
        assert result[1]["cve"]["id"] == "CVE-2024-0002"

    def test_empty_input_with_none_checkpoint(self):
        result = filter_cves_by_checkpoint([], None)
        assert result == []

    def test_all_items_newer_than_checkpoint(self):
        items = [
            _make_cve_item("CVE-2024-0001", "2024-06-01T00:00:00.000"),
            _make_cve_item("CVE-2024-0002", "2024-07-01T00:00:00.000"),
        ]
        result = filter_cves_by_checkpoint(items, "2024-01-01T00:00:00.000")
        assert result == items
