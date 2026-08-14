"""Feed ingestion utilities for downloading, decompressing, and parsing feeds.

Provides source-agnostic functions for:
- Downloading and decompressing gzipped feed files
- Parsing JSON feed data
- Fetching META files for SHA-256 hash comparison
"""

import gzip
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from lambdas.shared.exceptions import FeedDownloadError


def download_and_decompress(url: str, timeout: int = 30, max_size: int = 200_000_000) -> bytes:
    """Download a gzipped file and decompress in memory.

    Args:
        url: URL of the gzipped file to download.
        timeout: HTTP request timeout in seconds.
        max_size: Maximum allowed decompressed size in bytes (default 200 MB).

    Returns:
        Decompressed bytes content.

    Raises:
        FeedDownloadError: On network errors, non-200 HTTP responses,
            decompression failures, or if decompressed size exceeds max_size.
    """
    try:
        request = Request(url)
        response = urlopen(request, timeout=timeout)

        if response.status != 200:
            raise FeedDownloadError(
                source="feed_ingestion",
                operation="download_and_decompress",
                message=f"HTTP {response.status} from {url}",
            )

        compressed_data = response.read()
    except FeedDownloadError:
        raise
    except HTTPError as exc:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="download_and_decompress",
            message=f"HTTP {exc.code} from {url}: {exc.reason}",
        ) from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="download_and_decompress",
            message=f"Network error downloading {url}: {exc}",
        ) from exc

    try:
        decompressed_data = gzip.decompress(compressed_data)
    except (gzip.BadGzipFile, OSError, EOFError) as exc:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="download_and_decompress",
            message=f"Decompression failed for {url}: {exc}",
        ) from exc

    if len(decompressed_data) > max_size:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="download_and_decompress",
            message=(
                f"Decompressed size {len(decompressed_data)} bytes exceeds "
                f"max_size {max_size} bytes for {url}"
            ),
        )

    return decompressed_data


def parse_json_feed(data: bytes) -> dict:
    """Parse decompressed feed data as JSON.

    Args:
        data: Raw bytes of decompressed JSON feed content.

    Returns:
        Parsed JSON as a dictionary.

    Raises:
        FeedDownloadError: If the data is not valid JSON.
    """
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="parse_json_feed",
            message=f"Malformed JSON feed data: {exc}",
        ) from exc


def fetch_meta_sha256(meta_url: str, timeout: int = 10) -> str:
    """Fetch META file and extract SHA-256 hash string.

    The NVD META file is plain text with lines like:
        lastModifiedDate:2024-01-01T00:00:00-00:00
        size:12345678
        sha256:ABCDEF0123456789...

    Args:
        meta_url: URL of the META file.
        timeout: HTTP request timeout in seconds.

    Returns:
        The SHA-256 hex hash string (lowercase).

    Raises:
        FeedDownloadError: On network errors, non-200 HTTP responses,
            or if the SHA-256 line is not found in the META file.
    """
    try:
        request = Request(meta_url)
        response = urlopen(request, timeout=timeout)

        if response.status != 200:
            raise FeedDownloadError(
                source="feed_ingestion",
                operation="fetch_meta_sha256",
                message=f"HTTP {response.status} from {meta_url}",
            )

        content = response.read().decode("utf-8")
    except FeedDownloadError:
        raise
    except HTTPError as exc:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="fetch_meta_sha256",
            message=f"HTTP {exc.code} from {meta_url}: {exc.reason}",
        ) from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise FeedDownloadError(
            source="feed_ingestion",
            operation="fetch_meta_sha256",
            message=f"Network error fetching {meta_url}: {exc}",
        ) from exc

    for line in content.splitlines():
        if line.startswith("sha256:"):
            return line[len("sha256:") :].strip().lower()

    raise FeedDownloadError(
        source="feed_ingestion",
        operation="fetch_meta_sha256",
        message=f"No sha256 line found in META file at {meta_url}",
    )
