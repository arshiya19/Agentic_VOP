from __future__ import annotations

import time
from typing import Any

import httpx

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 0.5

# Socket-level and transport errors that are transient and should be retried
RETRYABLE_ERROR_TYPES = (
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.PoolTimeout,
    TimeoutError,
)


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json: Any | None = None,
    timeout: float | None = None,
    max_attempts: int = DEFAULT_RETRY_ATTEMPTS,
    backoff_factor: float = DEFAULT_BACKOFF_SECONDS,
    retry_statuses: set[int] = RETRYABLE_STATUS_CODES,
    run_id: str | None = None,
    agent: str | None = None,
    emit_fn: Any = None,
) -> httpx.Response:
    """Send an HTTP request with retry/backoff for transient failures.

    Retries on network errors, timeouts, and retryable HTTP statuses.
    Non-retryable status codes are raised immediately.

    Args:
        run_id: for trace logging (optional)
        agent: for trace logging (optional)
    """
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = client.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json,
                timeout=timeout,
            )

            if response.status_code in retry_statuses:
                error = httpx.HTTPStatusError(
                    f"Retryable HTTP status {response.status_code}",
                    request=response.request,
                    response=response,
                )
                raise error

            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            last_error = exc
            response = exc.response
            if response is not None and response.status_code not in retry_statuses:
                raise
            if attempt < max_attempts:
                _log_retry(run_id, agent, attempt, max_attempts, exc, emit_fn=emit_fn)
        except RETRYABLE_ERROR_TYPES as exc:
            last_error = exc
            if attempt < max_attempts:
                _log_retry(run_id, agent, attempt, max_attempts, exc, emit_fn=emit_fn)

        if attempt >= max_attempts:
            break

        time.sleep(backoff_factor * (2 ** (attempt - 1)))

    assert last_error is not None
    raise last_error


def _log_retry(
    run_id: str | None,
    agent: str | None,
    attempt: int,
    max_attempts: int,
    error: Exception,
    *,
    emit_fn: Any = None,
) -> None:
    """Log retry attempt for debugging. `emit_fn` (DI) defaults to public-schema
    emit_trace; demo callers pass emit_trace_demo to route into demo schema."""
    if run_id and agent:
        if emit_fn is None:
            from .trace import emit_trace  # noqa: PLC0415
            emit_fn = emit_trace

        error_type = type(error).__name__
        error_msg = str(error)[:150]
        emit_fn(
            run_id,
            agent,
            "MESSAGE",
            f"HTTP retry {attempt}/{max_attempts}: {error_type} — {error_msg}",
        )
