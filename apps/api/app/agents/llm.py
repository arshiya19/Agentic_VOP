"""LangChain chat-model factory with per-call token-usage tracing.

Public API:

    llm = get_chat_llm(run_id, "master", model="gpt-4o", temperature=0.1)
    plan = llm.with_structured_output(MasterPlan).invoke(messages)

Provider is inferred from the model name prefix:
  - "gpt-*", "o1-*", "o3-*" → OpenAI (ChatOpenAI)
  - "claude-*"              → Anthropic (ChatAnthropic)
  - "gemini-*"              → Google (ChatGoogleGenerativeAI)

A custom callback handler (`_TokenUsageCallback`) attaches to every call so
the Agents page still receives live TOKEN_USAGE events via `emit_trace()`.
The callback reads from LangChain's standardized `usage_metadata` field,
which all three providers populate uniformly.

Capture level: per individual LLM invocation — every `.invoke()` (or async
equivalent) is tracked separately, including parallel worker calls in
Sub-Agent 1 / Sub-Agent 2.
"""

from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.outputs import LLMResult
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

from ..config import settings


class _TokenUsageCallback(BaseCallbackHandler):
    """Emits a TOKEN_USAGE trace event after every LLM call.

    LangChain calls `on_llm_end(response, **kwargs)` when an LLM finishes.
    We pull token counts out of `response.llm_output["token_usage"]`
    (OpenAI format) and forward them via `emit_trace()` so the frontend
    sees identical events to the previous SDK-proxy implementation.
    """

    def __init__(self, run_id: str, agent: str, model: str) -> None:
        self._run_id = run_id
        self._agent = agent
        self._model = model

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:  # noqa: ARG002
        usage = self._extract_usage(response)
        if usage is None:
            return

        # Import here to avoid the circular trace → db → config → llm path.
        from .trace import emit_trace  # noqa: PLC0415

        emit_trace(
            self._run_id,
            self._agent,
            "MESSAGE",
            (
                f"LLM call — prompt: {usage['prompt_tokens']} tokens, "
                f"completion: {usage['completion_tokens']} tokens, "
                f"total: {usage['total_tokens']} tokens"
            ),
            payload={
                "event_subtype": "TOKEN_USAGE",
                "model": self._model,
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
                "total_tokens": usage["total_tokens"],
            },
        )

    @staticmethod
    def _extract_usage(response: LLMResult) -> dict[str, int] | None:
        """Pull token counts from LLMResult.

        LangChain places provider-specific data in `response.llm_output`.
        For ChatOpenAI this is `{"token_usage": {...}, "model_name": ...}`.
        On structured-output calls the same dict is populated.
        """
        llm_output = response.llm_output or {}
        usage = llm_output.get("token_usage") or {}
        if not usage:
            # Fall back to per-generation usage_metadata (newer LangChain versions).
            for gen_list in response.generations:
                for gen in gen_list:
                    msg = getattr(gen, "message", None)
                    meta = getattr(msg, "usage_metadata", None) if msg else None
                    if meta:
                        return {
                            "prompt_tokens": meta.get("input_tokens", 0),
                            "completion_tokens": meta.get("output_tokens", 0),
                            "total_tokens": meta.get("total_tokens", 0),
                        }
            return None
        return {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        }


def invoke_structured_with_retry(
    *,
    run_id: str,
    agent: str,
    schema: type,
    messages: list,
    attempts: list[tuple[float, str, int]],
    method: str = "function_calling",
) -> Any:
    """Invoke ChatOpenAI.with_structured_output with tiered retry.

    Each entry in `attempts` is `(temperature, model, max_tokens)`. The helper
    tries them in order and returns the first non-None structured result. A
    None return from `.invoke()` (model failed to call the tool — usually a
    max_tokens overflow) is converted into a retryable exception. The final
    exception propagates if every attempt fails.

    Per-attempt `max_tokens` lets callers escalate the completion budget on
    each retry — useful for inputs where the model occasionally needs more
    headroom to finish the structured-output tool call.

    `method="function_calling"` is the default because it tolerates
    `dict[str, Any]` fields in the schema; pass `method="json_schema"`
    to opt into strict mode for schemas without free-form objects.
    """
    last_err: Exception | None = None
    for temperature, model, max_tokens in attempts:
        try:
            llm = get_chat_llm(
                run_id=run_id,
                agent=agent,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            structured_llm = llm.with_structured_output(schema, method=method)
            result = structured_llm.invoke(messages)
            if result is None:
                raise ValueError(
                    "LLM did not invoke the structured-output tool "
                    "(likely hit max_tokens responding in prose)"
                )
            return result
        except Exception as e:  # noqa: BLE001
            last_err = e

    assert last_err is not None  # nosec B101
    raise last_err


def _infer_provider(model: str) -> str:
    """Map a model name to its provider via prefix matching.

    Unknown prefixes default to OpenAI so older configs keep working.
    """
    name = model.lower()
    if name.startswith("claude-"):
        return "anthropic"
    if name.startswith("gemini-"):
        return "google"
    return "openai"


def get_chat_llm(
    run_id: str,
    agent: str,
    model: str,
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> BaseChatModel:
    """Return a configured chat model (OpenAI / Anthropic / Google) that
    traces token usage per call.

    Provider is inferred from the model-name prefix (see `_infer_provider`),
    so callers don't need to pass it explicitly — switching a `prompt_db.model`
    row from "gpt-4o" to "claude-opus-4-7" routes through Anthropic.

    All three return types share `with_structured_output()` and `.invoke()`
    via LangChain's `BaseChatModel`, so the downstream retry helper works
    uniformly across providers.

    Args:
        run_id: agent_runs.run_id — passed into the callback for trace correlation.
        agent: "master" | "sub-agent-1" | "sub-agent-2" — labels the trace event.
        model: model name from prompt_db (e.g. "gpt-4o", "claude-opus-4-7", "gemini-2.0-pro").
        temperature: sampling temperature; retry helper escalates per attempt.
        max_tokens: completion cap; loaded from prompt_db.parameters when present.
    """
    callback = _TokenUsageCallback(run_id=run_id, agent=agent, model=model)
    provider = _infer_provider(model)

    if provider == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError(f"Model '{model}' requires ANTHROPIC_API_KEY in the environment.")
        # Anthropic requires max_tokens; default to a sane ceiling if unset.
        return ChatAnthropic(
            api_key=settings.anthropic_api_key,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens or 4096,
            timeout=120.0,
            max_retries=10,
            callbacks=[callback],
        )

    if provider == "google":
        if not settings.google_api_key:
            raise RuntimeError(f"Model '{model}' requires GOOGLE_API_KEY in the environment.")
        return ChatGoogleGenerativeAI(
            google_api_key=settings.google_api_key,
            model=model,
            temperature=temperature,
            max_output_tokens=max_tokens,
            timeout=120.0,
            max_retries=10,
            callbacks=[callback],
        )

    return ChatOpenAI(
        api_key=settings.openai_api_key,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=120.0,
        max_retries=10,
        callbacks=[callback],
    )
