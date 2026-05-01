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

    source: Literal["tenable", "trivy", "qualys", "owasp", "snyk", "osv"]
    source_vuln_id: str
    cve_id: str | None = None
    all_cves: list[str] = []
    title: str
    description: str | None = None
    severity: Literal["Info", "Low", "Medium", "High", "Critical"]
    cvss_score: float | None = None
    cvss_version: Literal["2.0", "3.0", "3.1"] | None = None
    solution: str | None = None
    asset_identity: dict[str, Any] = {}
    package: dict[str, Any] | None = None
    first_detected: datetime | None = None


class LLMEnrichmentDecision(BaseModel):
    """Sub-Agent 2's per-issue LLM output: risk reasoning + remediation.

    Used as the input_schema for the emit_enrichment_decision tool call.
    """

    model_config = ConfigDict(extra="forbid")

    derived_risk: float = Field(..., ge=0, le=100)
    risk_explanation: str = Field(..., min_length=10, max_length=600)
    likelihood: float = Field(..., ge=0, le=1)
    impact: float = Field(..., ge=0, le=1)
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
