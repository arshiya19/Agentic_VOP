"""Tool implementations for the agentic Sub-Agent 3 (Phase-2).

Each tool is a pure function or thin class the agent can call:
  - web_search: Tavily-backed live search
  - url_fetch: httpx + trafilatura content extraction
  - source_scorer: rank sources by authority tier

The agent_v2 module composes these into a LangGraph tool-loop.
"""
