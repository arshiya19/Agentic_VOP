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


class RemediationStep(BaseModel):
    """One step in a remediation or rollback plan, with its citation."""

    model_config = ConfigDict(extra="forbid")

    step: str = Field(..., min_length=10, max_length=500)
    source: str = Field(..., min_length=3, max_length=200)
    source_url: str = Field("", max_length=500)


class ValidationTest(BaseModel):
    """One concrete test (validation or regression) the operator can run."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=5, max_length=200)
    method: str = Field(..., min_length=2, max_length=50)
    command: str = Field(..., min_length=5, max_length=1000)
    expected: str = Field(..., min_length=5, max_length=400)
    source: str = Field(..., min_length=3, max_length=200)


class TestScript(BaseModel):
    """A runnable script that automates one or more validation tests."""

    model_config = ConfigDict(extra="forbid")

    language: Literal["bash", "python", "powershell", "yaml", "hcl"]
    description: str = Field(..., min_length=10, max_length=300)
    code: str = Field(..., min_length=20, max_length=3000)


class RollbackPlan(BaseModel):
    """Explainable rollback plan per Phase-1 doc §7.2.

    Same rigor as remediation: every rollback should justify whether it's
    technically possible, what preconditions apply, what limitations exist,
    and the reasoning behind the recommendation (not "just revert to X").
    """

    model_config = ConfigDict(extra="forbid")

    supported: bool = Field(..., description="True if rollback is technically possible for this finding")
    objective: str = Field(..., min_length=10, max_length=400)
    preconditions: list[str] = Field(default_factory=list, max_length=10)
    steps: list[RemediationStep] = Field(default_factory=list, max_length=10)
    validation: list[ValidationTest] = Field(default_factory=list, max_length=5)
    limitations: list[str] = Field(default_factory=list, max_length=10)
    explanation: str = Field(..., min_length=20, max_length=600,
                             description="WHY rollback is or isn't recommended for this specific finding")
    recommended_recovery: str = Field("", max_length=400,
                                      description="If supported=false, the alternative path (e.g. 'Restore from backup')")


class ValidationMetadata(BaseModel):
    """Audit trail for §7.1 — confirms the remediation was checked against
    authoritative sources, and at what tier.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["validated", "partial", "unvalidated"]
    sources: list[str] = Field(default_factory=list,
                               description="Citation names — e.g. ['AWS Documentation', 'NVD', 'CIS AWS 2.1.5']")
    timestamp: str = Field(..., description="ISO 8601 timestamp when validation was performed")
    confidence: Literal["high", "medium", "low"]


class RemediationPathway(BaseModel):
    """One way to remediate the finding (per Phase-1 doc §7.3).

    For Phase-1, every package has exactly 1 pathway. Schema supports
    multiple pathways for the Phase-2 multi-pathway flow without further
    architectural change.
    """

    model_config = ConfigDict(extra="forbid")

    # LLM-generated
    objective: str = Field(..., min_length=10, max_length=300)
    security_coverage: Literal["complete", "partial", "interim"]
    remediation_steps: list[RemediationStep] = Field(..., min_length=1, max_length=10)
    rollback_plan: RollbackPlan
    validation_tests: list[ValidationTest] = Field(..., min_length=1, max_length=10)
    test_scripts: list[TestScript] = Field(default_factory=list, max_length=5)
    execution_strategy: str = Field(..., min_length=50, max_length=600)
    advantages: list[str] = Field(default_factory=list, max_length=6)
    considerations: list[str] = Field(default_factory=list, max_length=6)

    # Code-attached (deterministic — filled by planner/confidence engine)
    validation_metadata: ValidationMetadata | None = None
    confidence_score: int | None = None
    confidence_components: dict[str, Any] | None = None


class LLMRemediationOutput(BaseModel):
    """Sub-Agent 3's LLM output (v1.1). Caller attaches issue_id, family,
    validation_metadata, confidence, approval_required, recommended_pathway_index
    AFTER the call.
    """

    model_config = ConfigDict(extra="forbid")

    finding: str = Field(..., min_length=20, max_length=400)
    root_cause: str = Field(..., min_length=20, max_length=400)
    impact: str = Field(..., min_length=20, max_length=400)
    pathways: list[RemediationPathway] = Field(..., min_length=1, max_length=3)


class RemediationPackage(BaseModel):
    """The full persisted artifact — Phase-1 Working Model §5 (v1.1 shape).

    Top-level header (Finding / Root Cause / Impact) is shared across
    pathways. Each pathway holds its own remediation/rollback/tests/confidence.
    `recommended_pathway_index` points at the pathway the planner suggests.
    Approval is package-level (one decision covers the chosen pathway).
    """

    model_config = ConfigDict(extra="forbid")

    # Caller-attached (deterministic)
    issue_id: int
    family: str

    # LLM-generated header (shared across pathways)
    finding: str
    root_cause: str
    impact: str

    # 1+ remediation pathways (Phase-1 always = 1)
    pathways: list[RemediationPathway]

    # Code-attached
    recommended_pathway_index: int = 0
    approval_required: Literal["auto", "single_approver", "multi_stage"] | None = None


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
