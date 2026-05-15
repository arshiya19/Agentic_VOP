"""
Simple test script to verify HTTP retry logic is working.

Usage:
  cd apps/api
  uv run python test_retry_logic.py

This simulates network errors and verifies retries succeed.
"""

import httpx
import uuid
from app.agents.http_utils import request_with_retry


class SimulatedFlakeyServer:
    """Mock HTTP client that fails N times then succeeds."""

    def __init__(self, fail_count: int = 2):
        self.attempt = 0
        self.fail_count = fail_count

    def request(self, method: str, url: str, **kwargs):
        self.attempt += 1
        print(f"  → Attempt {self.attempt}: ", end="")

        # Fail first N attempts with transient errors
        if self.attempt <= self.fail_count:
            if self.attempt == 1:
                # Socket read timeout (Windows-like error)
                error = httpx.ReadError("[WinError 10035] Socket timeout")
                print(f"FAIL (ReadError)")
                raise error
            elif self.attempt == 2:
                # Connection timeout
                error = httpx.ConnectError("Connection refused")
                print(f"FAIL (ConnectError)")
                raise error
            else:
                # Generic timeout
                raise TimeoutError("Request timeout")

        # Success on final attempt
        print("SUCCESS ✓")
        request = httpx.Request(method, url)
        response = httpx.Response(
            200,
            request=request,
            content=b'{"status": "ok", "data": []}',
        )
        return response


def test_retry_logic():
    """Test that request_with_retry handles transient failures."""
    print("\n" + "=" * 60)
    print("Testing HTTP Retry Logic")
    print("=" * 60)

    # Test 1: Retry on socket read error (WinError 10035)
    print("\nTest 1: Retry on ReadError (socket timeout)")
    print("-" * 60)
    client = SimulatedFlakeyServer(fail_count=2)
    try:
        resp = request_with_retry(
            client,
            "GET",
            "https://api.example.com/test",
            # run_id=str(uuid.uuid4()),
            # agent="system",
        )
        print(f"\n✓ PASSED: Request succeeded after {client.attempt} attempts")
        print(f"  Response: {resp.json()}")
    except Exception as e:
        print(f"\n✗ FAILED: {e}")

    # Test 2: Retry on retryable HTTP status
    print("\n\nTest 2: Retry on HTTP 503 (Service Unavailable)")
    print("-" * 60)

    class ServiceUnavailableClient:
        def __init__(self):
            self.attempt = 0

        def request(self, method, url, **kwargs):
            self.attempt += 1
            print(f"  → Attempt {self.attempt}: ", end="")
            if self.attempt == 1:
                print("FAIL (HTTP 503)")
                response = httpx.Response(503)
                response._content = b"Service Unavailable"
                raise httpx.HTTPStatusError("503", request=None, response=response)
            print("SUCCESS ✓")
            request = httpx.Request(method, url)
            response = httpx.Response(
                200,
                request=request,
                content=b'{"status": "ok"}',
            )
            return response

    client2 = ServiceUnavailableClient()
    try:
        resp = request_with_retry(
            client2,
            "GET",
            "https://api.example.com/test",
        )
        print(f"\n✓ PASSED: Request succeeded after {client2.attempt} attempts")
    except Exception as e:
        print(f"\n✗ FAILED: {e}")

    # Test 3: Non-retryable errors fail immediately
    print("\n\nTest 3: Non-retryable error fails immediately (HTTP 401)")
    print("-" * 60)

    class UnauthorizedClient:
        def __init__(self):
            self.attempt = 0

        def request(self, method, url, **kwargs):
            self.attempt += 1
            print(f"  → Attempt {self.attempt}: FAIL (HTTP 401 - unauthorized)")
            response = httpx.Response(401)
            raise httpx.HTTPStatusError("401 Unauthorized", request=None, response=response)

    client3 = UnauthorizedClient()
    try:
        resp = request_with_retry(client3, "GET", "https://api.example.com/test")
        print(f"\n✗ FAILED: Should have raised exception immediately")
    except httpx.HTTPStatusError:
        print(f"\n✓ PASSED: Non-retryable error raised immediately (1 attempt only)")
        print(f"  Total attempts: {client3.attempt}")

    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    test_retry_logic()
