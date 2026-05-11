"""OpenAI SDK client wrapper with per-call token-usage tracing.

`get_client()` — kept for backward compatibility, returns the raw OpenAI singleton.
`get_llm(run_id, agent)` — returns a context-aware wrapper whose
    `chat.completions.create()` is a drop-in replacement that:
      1. Calls the real OpenAI API.
      2. Reads response.usage (prompt_tokens, completion_tokens, total_tokens).
      3. Emits a TOKEN_USAGE trace event so the Agents page shows live token counts.

Capture level: per individual LLM call — every chat.completions.create()
invocation is tracked separately, including parallel worker calls in
Sub-Agent 1 and Sub-Agent 2.
"""

from openai import OpenAI
from openai.types.chat import ChatCompletion

from ..config import settings


_client: OpenAI | None = None


def get_client() -> OpenAI:
    """Lazy singleton OpenAI client with generous retry budget."""
    global _client
    if _client is None:
        _client = OpenAI(
            api_key=settings.openai_api_key,
            max_retries=10,
            timeout=120.0,
        )
    return _client


class _CompletionsProxy:
    """Proxies chat.completions so callers use the identical .create() signature."""

    def __init__(self, run_id: str, agent: str) -> None:
        self._run_id = run_id
        self._agent = agent

    def create(self, **kwargs) -> ChatCompletion:
        response = get_client().chat.completions.create(**kwargs)
        self._emit_usage(response, kwargs.get("model", "unknown"))
        return response

    def _emit_usage(self, response: ChatCompletion, model: str) -> None:
        usage = response.usage
        if not usage:
            return
        # Import here to avoid circular imports (trace → db → config → llm)
        from .trace import emit_trace  # noqa: PLC0415

        emit_trace(
            self._run_id,
            self._agent,
            "MESSAGE",
            (
                f"LLM call — prompt: {usage.prompt_tokens} tokens, "
                f"completion: {usage.completion_tokens} tokens, "
                f"total: {usage.total_tokens} tokens"
            ),
            payload={
                "event_subtype": "TOKEN_USAGE",
                "model": model,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            },
        )

    def extract_usage(self, response: ChatCompletion) -> dict:
        """Return token counts from a response as a plain dict (zeros if missing)."""
        usage = response.usage
        if not usage:
            return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        return {
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
        }


class _LLMContext:
    """Mimics the openai.OpenAI client shape (client.chat.completions.create)."""

    def __init__(self, run_id: str, agent: str) -> None:
        self.chat = _ChatProxy(run_id, agent)


class _ChatProxy:
    def __init__(self, run_id: str, agent: str) -> None:
        self.completions = _CompletionsProxy(run_id, agent)


def get_llm(run_id: str, agent: str) -> _LLMContext:
    """Return a context-aware LLM handle that traces token usage per call.

    Usage (identical to the raw client):
        llm = get_llm(run_id, "master")
        response = llm.chat.completions.create(model=..., messages=..., ...)
    """
    return _LLMContext(run_id, agent)
