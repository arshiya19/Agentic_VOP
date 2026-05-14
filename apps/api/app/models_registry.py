"""Curated list of LLM models the UI can offer for each agent.

Each model in this registry has been confirmed to support LangChain's
`with_structured_output(method="function_calling")` (or equivalent native
tool-use), which is what every agent relies on.

The provider for a model is inferred from its name prefix in `llm.py`, so
all the UI / API needs to track is the model id.
"""

from __future__ import annotations


AVAILABLE_MODELS: dict[str, list[dict[str, str]]] = {
    "openai": [
        {"id": "gpt-4o", "label": "GPT-4o"},
        {"id": "gpt-4o-mini", "label": "GPT-4o mini"},
        {"id": "gpt-4-turbo", "label": "GPT-4 Turbo"},
        {"id": "o3-mini", "label": "o3 mini"},
        {"id": "o1-mini", "label": "o1 mini"},
    ],
    "anthropic": [
        {"id": "claude-opus-4-7", "label": "Claude Opus 4.7"},
        {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
        {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5"},
        {"id": "claude-3-7-sonnet-latest", "label": "Claude 3.7 Sonnet"},
        {"id": "claude-3-5-sonnet-latest", "label": "Claude 3.5 Sonnet"},
    ],
    "google": [
        {"id": "gemini-2.0-pro", "label": "Gemini 2.0 Pro"},
        {"id": "gemini-2.0-flash", "label": "Gemini 2.0 Flash"},
        {"id": "gemini-1.5-pro", "label": "Gemini 1.5 Pro"},
        {"id": "gemini-1.5-flash", "label": "Gemini 1.5 Flash"},
        {"id": "gemini-1.5-flash-8b", "label": "Gemini 1.5 Flash 8B"},
    ],
}


# The single tested-and-recommended model per agent. The UI shows a
# "Recommended" badge for these and warns users when they pick something else.
RECOMMENDED_MODELS: dict[str, str] = {
    "master": "gpt-4o",
    "sub-agent-1": "gpt-4o-mini",
    "sub-agent-2": "gpt-4o-mini",
}


_ALL_MODEL_IDS: set[str] = {
    model["id"] for provider_models in AVAILABLE_MODELS.values() for model in provider_models
}


def is_valid_model(model_id: str) -> bool:
    """True iff `model_id` is in the curated whitelist."""
    return model_id in _ALL_MODEL_IDS
