"""OpenAI SDK client wrapper. Single shared instance reused across agent calls.

`max_retries=10` lets the SDK ride out short 429 bursts with built-in
exponential backoff before propagating to our code.
"""

from openai import OpenAI

from ..config import settings

_client: OpenAI | None = None


def get_client() -> OpenAI:
    """Lazy singleton OpenAI client with generous retry budget."""
    global _client
    if _client is None:
        _client = OpenAI(
            api_key=settings.openai_api_key,
            max_retries=10,    # default is 2; 10 covers most TPM bursts
            timeout=120.0,
        )
    return _client
