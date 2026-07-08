"""Per-run agent budget tracker.

Every tool call the agent makes (web_search, url_fetch, future tools) records
against the same budget instance. When either the call-count or dollar cap
is hit, the next `can_call()` returns False and the agent should stop
calling tools + fall back to the hybrid planner.

Defaults come from settings but callers can override for tests / tight demos.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ....config import settings


# Estimated per-call cost by tool. Real-world costs vary — these are pessimistic
# for budget math. Free tiers return 0 real cost; the counter still fires so we
# exercise cap logic during dev.
_COST_PER_TOOL_USD = {
    "web_search": 0.05,   # Tavily advanced tier estimate
    "url_fetch": 0.001,    # Effectively free (bandwidth only), rounded up
}


@dataclass
class AgentBudget:
    max_calls: int = field(default_factory=lambda: settings.agent_max_tool_calls)
    max_cost_usd: float = field(default_factory=lambda: settings.agent_max_cost_usd)

    call_count: int = 0
    cost_accrued_usd: float = 0.0
    # Per-tool call counts, for observability
    by_tool: dict[str, int] = field(default_factory=dict)

    def can_call(self) -> tuple[bool, str]:
        """Return (allowed, reason_if_denied)."""
        if self.call_count >= self.max_calls:
            return False, f"Max tool calls reached ({self.call_count}/{self.max_calls})"
        if self.cost_accrued_usd >= self.max_cost_usd:
            return (
                False,
                f"Cost cap reached (${self.cost_accrued_usd:.2f}/${self.max_cost_usd:.2f})",
            )
        return True, ""

    def record_call(self, tool: str) -> None:
        """Record one tool call with tool-specific cost."""
        self.call_count += 1
        self.cost_accrued_usd += _COST_PER_TOOL_USD.get(tool, 0.01)
        self.by_tool[tool] = self.by_tool.get(tool, 0) + 1

    def summary(self) -> dict:
        """Compact summary for trace payloads."""
        return {
            "call_count": self.call_count,
            "max_calls": self.max_calls,
            "cost_usd": round(self.cost_accrued_usd, 4),
            "max_cost_usd": self.max_cost_usd,
            "by_tool": dict(self.by_tool),
        }
