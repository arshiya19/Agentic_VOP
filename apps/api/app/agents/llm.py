"""Anthropic SDK client wrapper. Single shared instance with prompt caching enabled."""

from anthropic import Anthropic

from ..config import settings

_client: Anthropic | None = None


def get_client() -> Anthropic:
    """Lazy singleton Anthropic client."""
    global _client
    if _client is None:
        _client = Anthropic(api_key=settings.anthropic_api_key)
    return _client
