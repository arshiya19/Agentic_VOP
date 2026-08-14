"""Unit tests for the feed_ingestion module."""

import gzip
import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from lambdas.shared.exceptions import FeedDownloadError
from lambdas.shared.feed_ingestion import (
    download_and_decompress,
    fetch_meta_sha256,
    parse_json_feed,
)


class TestParseJsonFeed:
    """Tests for parse_json_feed."""

    def test_valid_json_parsed(self):
        data = json.dumps({"CVE_Items": [{"id": "CVE-2024-1234"}]}).encode()
        result = parse_json_feed(data)
        assert result == {"CVE_Items": [{"id": "CVE-2024-1234"}]}

    def test_empty_object(self):
        result = parse_json_feed(b"{}")
        assert result == {}

    def test_invalid_json_raises_feed_download_error(self):
        with pytest.raises(FeedDownloadError) as exc_info:
            parse_json_feed(b"not valid json")
        assert exc_info.value.source == "feed_ingestion"
        assert exc_info.value.operation == "parse_json_feed"
        assert "Malformed JSON" in str(exc_info.value)

    def test_invalid_encoding_raises_feed_download_error(self):
        # Invalid UTF-8 sequence
        with pytest.raises(FeedDownloadError) as exc_info:
            parse_json_feed(b"\xff\xfe")
        assert exc_info.value.operation == "parse_json_feed"


class TestDownloadAndDecompress:
    """Tests for download_and_decompress."""

    def _make_gzipped(self, content: bytes) -> bytes:
        return gzip.compress(content)

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_successful_download_and_decompress(self, mock_urlopen):
        original = b"hello world"
        compressed = self._make_gzipped(original)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = compressed
        mock_urlopen.return_value = mock_response

        result = download_and_decompress("https://example.com/feed.gz")
        assert result == original

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_max_size_exceeded_raises_error(self, mock_urlopen):
        original = b"x" * 1000
        compressed = self._make_gzipped(original)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = compressed
        mock_urlopen.return_value = mock_response

        with pytest.raises(FeedDownloadError) as exc_info:
            download_and_decompress("https://example.com/feed.gz", max_size=500)
        assert "exceeds max_size" in str(exc_info.value)

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_http_error_raises_feed_download_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://example.com/feed.gz", 404, "Not Found", {}, None
        )

        with pytest.raises(FeedDownloadError) as exc_info:
            download_and_decompress("https://example.com/feed.gz")
        assert "HTTP 404" in str(exc_info.value)
        assert exc_info.value.operation == "download_and_decompress"

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_url_error_raises_feed_download_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")

        with pytest.raises(FeedDownloadError) as exc_info:
            download_and_decompress("https://example.com/feed.gz")
        assert "Network error" in str(exc_info.value)

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_invalid_gzip_raises_feed_download_error(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"not gzipped data"
        mock_urlopen.return_value = mock_response

        with pytest.raises(FeedDownloadError) as exc_info:
            download_and_decompress("https://example.com/feed.gz")
        assert "Decompression failed" in str(exc_info.value)

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_timeout_error_raises_feed_download_error(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Request timed out")

        with pytest.raises(FeedDownloadError) as exc_info:
            download_and_decompress("https://example.com/feed.gz")
        assert "Network error" in str(exc_info.value)


class TestFetchMetaSha256:
    """Tests for fetch_meta_sha256."""

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_extracts_sha256_from_meta_content(self, mock_urlopen):
        meta_content = (
            "lastModifiedDate:2024-01-15T12:00:00-00:00\nsize:12345678\nsha256:ABC123DEF456789\n"
        )

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = meta_content.encode("utf-8")
        mock_urlopen.return_value = mock_response

        result = fetch_meta_sha256("https://example.com/feed.meta")
        assert result == "abc123def456789"  # lowercased

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_sha256_line_with_whitespace(self, mock_urlopen):
        meta_content = "sha256:  DEADBEEF0123  \n"

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = meta_content.encode("utf-8")
        mock_urlopen.return_value = mock_response

        result = fetch_meta_sha256("https://example.com/feed.meta")
        assert result == "deadbeef0123"

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_no_sha256_line_raises_error(self, mock_urlopen):
        meta_content = "lastModifiedDate:2024-01-15\nsize:12345\n"

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = meta_content.encode("utf-8")
        mock_urlopen.return_value = mock_response

        with pytest.raises(FeedDownloadError) as exc_info:
            fetch_meta_sha256("https://example.com/feed.meta")
        assert "No sha256 line found" in str(exc_info.value)

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_network_error_raises_feed_download_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("DNS lookup failed")

        with pytest.raises(FeedDownloadError) as exc_info:
            fetch_meta_sha256("https://example.com/feed.meta")
        assert "Network error" in str(exc_info.value)
        assert exc_info.value.operation == "fetch_meta_sha256"

    @patch("lambdas.shared.feed_ingestion.urlopen")
    def test_http_error_raises_feed_download_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://example.com/feed.meta", 503, "Service Unavailable", {}, None
        )

        with pytest.raises(FeedDownloadError) as exc_info:
            fetch_meta_sha256("https://example.com/feed.meta")
        assert "HTTP 503" in str(exc_info.value)
