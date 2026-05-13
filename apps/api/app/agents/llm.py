"""LangChain `ChatOpenAI` factory with per-call token-usage tracing.

Replaces the previous raw-OpenAI-SDK proxy. The public API is now:

    llm = get_chat_llm(run_id, "master", model="gpt-4o", temperature=0.1)
    plan = llm.with_structured_output(MasterPlan).invoke(messages)

A custom callback handler (`_TokenUsageCallback`) attaches to every call so
the Agents page still receives live TOKEN_USAGE events via `emit_trace()`.

Capture level: per individual LLM invocation — every `.invoke()` (or async
equivalent) is tracked separately, including parallel worker calls in
Sub-Agent 1 / Sub-Agent 2.
"""

from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
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


def get_chat_llm(
    run_id: str,
    agent: str,
    model: str,
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> ChatOpenAI:
    """Return a configured ChatOpenAI that traces token usage per call.

    Args:
        run_id: agent_runs.run_id — passed into the callback for trace correlation.
        agent: "master" | "sub-agent-1" | "sub-agent-2" — labels the trace event.
        model: model name from prompt_db (e.g. "gpt-4o", "gpt-4o-mini").
        temperature: sampling temperature; Sub-1 / Sub-2 use retry escalation 0.1 → 0.6 → 0.9.
        max_tokens: completion cap; loaded from prompt_db.parameters when present.

    Usage with structured output:
        llm = get_chat_llm(run_id, "master", "gpt-4o", temperature=0.1)
        plan = llm.with_structured_output(MasterPlan).invoke([
            SystemMessage(content="..."),
            HumanMessage(content="..."),
        ])
    """
    callback = _TokenUsageCallback(run_id=run_id, agent=agent, model=model)
    return ChatOpenAI(
        api_key=settings.openai_api_key,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=120.0,
        max_retries=10,
        callbacks=[callback],
    )
