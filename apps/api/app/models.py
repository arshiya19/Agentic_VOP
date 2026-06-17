from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class TriggerTargets(BaseModel):
    scanners: list[str] = Field(..., min_length=1)
    scope: list[str] = []
    priority: Literal["low", "normal", "critical"] = "normal"


class TriggerEvent(BaseModel):
    """Payload sent by the UI when a user clicks 'Fetch findings'."""

    event_id: str = Field(..., min_length=1, max_length=128)
    persona: str = "security-analyst"
    action: Literal["FETCH", "ENRICH", "FULL"] = "FETCH"
    targets: TriggerTargets
    knowledge_layer_ready: bool = True


class RunCreated(BaseModel):
    run_id: str
    event_id: str
    status: str


class LLMNormalizedIssue(BaseModel):
    """The fields Sub-Agent 1 (LLM) is responsible for producing.

    Used as the function-call input_schema for the LLM. The LLM's output is
    guaranteed by the API to match this schema — no JSON parsing required.

    Excluded from the LLM's responsibility (added by code):
      - source_raw       (the original raw row, attached verbatim by code)
      - agent_run_id     (set from the run context)
    """

    model_config = ConfigDict(extra="forbid")

    # Open string so user-registered scanners (via the Integrations page) work.
    # Sub-Agent 1 overrides this with the actual tool slug after the LLM call,
    # so the value the LLM returns here is advisory only.
    source: str
    source_vuln_id: str
    cve_id: str | None = None
    all_cves: list[str] = []
    # cwe_id is populated by Sub-Agent 1 when the raw row references one
    # directly (common for SAST scanners like Bandit/Semgrep/Snyk-Code that
    # produce code-level weakness findings without a CVE). When set, Sub-Agent 2
    # routes enrichment through MITRE directly, skipping the NVD-per-CVE lookup.
    cwe_id: str | None = None
    title: str
    description: str | None = None
    severity: Literal["Info", "Low", "Medium", "High", "Critical"]
    cvss_score: float | None = None
    cvss_version: Literal["2.0", "3.0", "3.1", "4.0"] | None = None
    # Raw CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:H/..."). When the LLM
    # spots one in the raw row, it lifts it here verbatim — Sub-Agent 1's
    # deterministic post-LLM step then parses it to fill cvss_score +
    # cvss_version. Lifts the LLM out of doing arithmetic it does poorly.
    cvss_vector: str | None = None
    solution: str | None = None
    asset_identity: dict[str, Any] = {}
    package: dict[str, Any] | None = None
    first_detected: datetime | None = None


class LLMEnrichmentDecision(BaseModel):
    """Sub-Agent 2's per-issue LLM output — prose only.

    Used as the input_schema for the emit_enrichment_decision tool call.

    As of prompt v1.4, the LLM no longer outputs the numeric score —
    a deterministic Python formula computes derived_risk, priority, and the
    factor breakdown (stored in `components_summary`). The LLM's job is now
    to write the narrative that explains WHY the formula produced that
    score, and to write a concrete remediation suggestion.
    """

    model_config = ConfigDict(extra="forbid")

    risk_explanation: str = Field(..., min_length=10, max_length=600)
    remediation_suggestion: str = Field(..., min_length=10, max_length=600)


class MasterPlanStep(BaseModel):
    """One step in the Master Agent's plan."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["FETCH", "ENRICH"]
    tool: str | None = None  # required when kind == "FETCH"
    notes: str | None = None  # 1-line reasoning


class MasterPlan(BaseModel):
    """Master Agent's LLM-produced plan: ordered steps for the run."""

    model_config = ConfigDict(extra="forbid")

    plan_summary: str = Field(..., min_length=10, max_length=500)
    steps: list[MasterPlanStep] = Field(..., min_length=1)
