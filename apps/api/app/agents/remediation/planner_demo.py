"""Sub-Agent 3 (Remediation Planner) — DEMO orchestrator.

For each enriched issue in demo.issues (agent_run_id = current demo run):
  1. Classify family (public_exposure / network_exposure / injection /
     vulnerable_dependency / os_vulnerability)
  2. Load the pattern from public.remediation_patterns (shared config)
  3. Load the asset from demo.assets (via asset_identity match — no view)
  4. Load the sub-agent-3 prompt from public.prompt_db (shared config)
  5. Call the LLM (v1.4 prompt — includes issue.solution +
     issue.remediation_suggestion as hints)
  6. Attach validation metadata + confidence to each pathway
  7. Persist the RemediationPackage to demo.remediation_packages

Reuses pure helpers from `planner.py`:
  _validation_metadata_for, _issue_payload, _pattern_payload,
  _derive_approval, classify_finding, compute_confidence

Key schema difference vs planner.py's plan_remediation():
  planner.py uses `issue_with_asset` VIEW for asset lookup — that view
  doesn't exist in the demo schema (migration 0046 only mirrored the 6
  base tables, not views). This orchestrator does the asset match directly
  against demo.assets using the same identity keys the view checks.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ...config import settings
from ...db import supabase_admin, supabase_admin_demo
from ...models import LLMRemediationOutput, RemediationPackage, RemediationPathway
from ..llm import invoke_structured_with_retry
from ..trace_demo import emit_trace_demo
from .classifier import classify_finding
from .confidence import compute_confidence, compute_confidence_agentic
from .planner import (
    _agent_validation_metadata,
    _derive_approval,
    _extract_iac_context,
    _issue_payload,
    _pattern_payload,
    _validation_metadata_for,
)


def run_demo_remediation(run_id: str) -> dict:
    """Generate + persist RemediationPackages for every demo issue in this run.

    Returns {"planned": N, "persisted": N, "failed": N}.
    """
    sb_demo = supabase_admin_demo()
    sb_pub = supabase_admin()  # for prompt_db + remediation_patterns (shared)

    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        "Loading enriched issues from demo.issues for this run",
    )

    issues = sb_demo.table("issues").select("*").eq("agent_run_id", run_id).execute().data or []

    if not issues:
        emit_trace_demo(
            run_id,
            "sub-agent-3",
            "DONE",
            "REMEDIATE_DONE — no issues to remediate",
            payload={"from": "sub-agent-3", "status": "REMEDIATE_DONE", "planned": 0},
        )
        return {"planned": 0, "persisted": 0, "failed": 0}

    # Batch-fetch raw_findings so the classifier can use raw.resource for
    # deterministic family classification (Checkov normalized titles are
    # just the check_id, so title-keyword rules fail without this).
    raw_by_id: dict[int, dict] = {}
    raw_ids = [i["raw_finding_id"] for i in issues if i.get("raw_finding_id") is not None]
    if raw_ids:
        raw_rows = (
            sb_pub.table("raw_findings").select("id, raw").in_("id", raw_ids).execute().data or []
        )
        raw_by_id = {r["id"]: (r.get("raw") or {}) for r in raw_rows}

    def _raw_for(issue: dict) -> dict | None:
        return raw_by_id.get(issue.get("raw_finding_id"))

    # Load pattern index for all seen families in ONE query (cheap).
    families_seen = {classify_finding(i, raw=_raw_for(i)) for i in issues}
    families_seen.discard("unknown")
    patterns_by_family: dict[str, dict] = {}
    if families_seen:
        rows = (
            sb_pub.table("remediation_patterns")
            .select("*")
            .in_("family", list(families_seen))
            .execute()
            .data
            or []
        )
        patterns_by_family = {r["family"]: r for r in rows}

    # Load Sub-Agent 3 (HYBRID fallback) prompt via the master router.
    # Router picks the most-specific prompt available in prompt_db based on
    # (source, family) with fallback to the generic sub-agent-3 v1.4 row.
    # Today only the generic row exists so behavior is identical to the old
    # hardcoded query. Specialized prompts (e.g. sub-agent-3-trivy-os) will
    # be picked up automatically once seeded.
    #
    # NOTE: source/family are per-issue, but we load a default prompt once
    # here for the outer loop's trace event. Per-issue routing happens inside
    # _plan_and_enrich (agent_v2) so each issue gets its own specialized prompt.
    from .prompt_router import load_sa3_prompt  # noqa: PLC0415

    prompt_row = load_sa3_prompt(sb_pub, source=None, family=None, default_version="v1.4")

    # Pre-load all demo.assets rows once and build a lookup index by identity.
    all_assets = sb_demo.table("assets").select("*").execute().data or []

    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"Loaded {len(issues)} issue(s), {len(patterns_by_family)} pattern(s), "
        f"{len(all_assets)} asset(s). Prompt {prompt_row['agent']}@{prompt_row['version']} "
        f"({prompt_row['model']})",
    )

    planned = persisted = failed = 0

    for issue in issues:
        try:
            family = classify_finding(issue, raw=_raw_for(issue))
            if family == "unknown":
                emit_trace_demo(
                    run_id,
                    "sub-agent-3",
                    "ERROR",
                    f"Issue {issue.get('id')} did not classify — skipping",
                )
                failed += 1
                continue

            pattern = patterns_by_family.get(family)
            if pattern is None:
                emit_trace_demo(
                    run_id,
                    "sub-agent-3",
                    "ERROR",
                    f"No pattern for family='{family}' — skipping issue {issue.get('id')}",
                )
                failed += 1
                continue

            asset = _lookup_demo_asset(all_assets, issue)

            raw = _raw_for(issue)
            pkg = _plan_and_enrich(run_id, prompt_row, issue, pattern, asset, family, sb_pub, raw)
            planned += 1

            _persist_to_demo(sb_demo, pkg, run_id)
            persisted += 1

            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"Package generated for issue {issue['id']} "
                f"(family={family}, confidence={pkg.pathways[pkg.recommended_pathway_index].confidence_score})",
            )
        except Exception as e:  # noqa: BLE001
            failed += 1
            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"Package generation failed for issue {issue.get('id')} "
                f"({type(e).__name__}): {str(e)[:250]}",
            )

    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "DONE",
        f"REMEDIATE_DONE — {planned} planned, {persisted} persisted, {failed} failed",
        payload={
            "from": "sub-agent-3",
            "status": "REMEDIATE_DONE",
            "planned": planned,
            "persisted": persisted,
            "failed": failed,
        },
    )
    return {"planned": planned, "persisted": persisted, "failed": failed}


def _lookup_demo_asset(all_assets: list[dict], issue: dict) -> dict:
    """Match an issue to a demo asset using the same identity keys as the
    real issue_with_asset view (project / repo / name / os → name/aliases; hostname; ipv4).
    Returns trimmed dict of fields the LLM needs, or {} if unattributed.
    """
    identity = issue.get("asset_identity") or {}
    project = identity.get("project")
    repo = identity.get("repo")
    name = identity.get("name")
    os_id = identity.get("os")
    hostname = identity.get("hostname")
    ipv4 = identity.get("ipv4")

    for a in all_assets:
        aliases = a.get("aliases") or []
        if project and (a.get("name") == project or project in aliases):
            return _trim_asset(a)
        if repo and (a.get("name") == repo or repo in aliases):
            return _trim_asset(a)
        if name and (a.get("name") == name or name in aliases):
            return _trim_asset(a)
        if os_id and (a.get("name") == os_id or os_id in aliases):
            return _trim_asset(a)
        if hostname and (a.get("hostname") == hostname or hostname in aliases):
            return _trim_asset(a)
        if ipv4 and a.get("ip_address") == ipv4:
            return _trim_asset(a)
    return {}


def _trim_asset(a: dict) -> dict:
    return {
        "name": a.get("name"),
        "application_name": a.get("application_name"),
        "environment": a.get("environment"),
        "exposure": a.get("exposure"),
        "business_criticality": a.get("business_criticality"),
        "data_classification": a.get("data_classification"),
        "compliance_tags": a.get("compliance_tags") or [],
    }


def _plan_and_enrich(
    run_id: str,
    prompt_row: dict,
    issue: dict,
    pattern: dict,
    asset: dict,
    family: str,
    sb_pub,
    raw: dict | None = None,
) -> RemediationPackage:
    """Try agentic path first (v2.0). On success, validation_metadata +
    confidence derive from the agent's actual citations + verifier report
    (pattern NOT used). On failure, fall back to hybrid v1.4 with pattern
    adaptation.

    `raw` is the raw_findings.raw jsonb for this issue (or None). Used for
    IaC context extraction (file_path, working_directory, resource_name,
    scanner_type) that SA3 v2.4's prompt needs to decide IaC-first vs
    direct-cloud fix shape.
    """
    agent_result = None  # tuple (LLMRemediationOutput, VerificationReport) | None
    llm_output: LLMRemediationOutput | None = None

    # --- Try KB DIRECT REPLAY first (fastest path — no web search) ---
    # If the knowledge base has a verified successful recipe for this exact
    # check_id + resource_type, adapt it via a single constrained LLM call
    # and return immediately. ~3 seconds, deterministic, no Tavily usage.
    try:
        from .kb_replay import try_kb_replay  # noqa: PLC0415

        kb_replay_output, kb_replay_id = try_kb_replay(
            issue=issue,
            family=family,
            raw=raw,
            sb=sb_pub,
            run_id=run_id,
            emit_fn=emit_trace_demo,
        )

        if kb_replay_output is not None:
            from ...models import RemediationPathway  # noqa: PLC0415, F401

            enriched_pathways: list[RemediationPathway] = []
            for pathway in kb_replay_output.pathways:
                pathway.confidence_score = 95
                pathway.confidence_components = {
                    "source": "kb_replay",
                    "kb_id": kb_replay_id,
                    "reason": "Proven fix replayed from knowledge base",
                }
                enriched_pathways.append(pathway)

            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"📚 KB replay path complete — returning package from KB #{kb_replay_id} "
                f"(confidence=95, family={family}). Skipping agentic/hybrid.",
            )

            return RemediationPackage(
                issue_id=int(issue["id"]),
                family=family,
                finding=kb_replay_output.finding,
                root_cause=kb_replay_output.root_cause,
                impact=kb_replay_output.impact,
                pathways=enriched_pathways,
                recommended_pathway_index=0,
                approval_required="auto",
            )
    except Exception as e:  # noqa: BLE001
        emit_trace_demo(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"KB replay module raised: {type(e).__name__}: {str(e)[:200]} "
            "— continuing with agentic/hybrid path.",
        )

    # --- AGENTIC path (Phase-2 default) ---
    if settings.tavily_api_key:
        from .agent_v2 import run_agentic_planner  # noqa: PLC0415

        try:
            # Augment issue with IaC context so SA3 v2.4's prompt has file_path,
            # working_directory, resource_name, scanner_type. Preserves original
            # issue for downstream persistence.
            agent_issue = {**issue, **_extract_iac_context(issue, raw)}

            # For container-image scanners, resolve dockerfile_path dynamically
            # from connection_registry metadata (same lookup SA4 does). This gives
            # SA3's LLM the correct paths to generate commands against.
            source = (issue.get("source") or "").lower()
            if not agent_issue.get("file_path") and "trivy-image" in source:
                try:
                    reg_row = sb_pub.table("connection_registry").select("metadata").eq("tool", issue.get("source")).single().execute().data
                    reg_meta = (reg_row or {}).get("metadata") or {}
                    if reg_meta.get("dockerfile_path"):
                        agent_issue["file_path"] = reg_meta["dockerfile_path"]
                        agent_issue["working_directory"] = reg_meta.get("build_directory") or reg_meta["dockerfile_path"].rsplit("/", 1)[0]
                    # Also set resource_name to image ref from raw target
                    if not agent_issue.get("resource_name") and raw:
                        target = raw.get("target") or raw.get("Target") or ""
                        image_ref = target.split("(")[0].strip() if "(" in target else target
                        if image_ref:
                            agent_issue["resource_name"] = image_ref
                    # Inject fix_pattern so SA3 knows the correct fix shape for this image type
                    if reg_meta.get("fix_pattern"):
                        agent_issue["fix_pattern"] = reg_meta["fix_pattern"]
                except Exception:  # noqa: BLE001
                    pass

            agent_result = run_agentic_planner(
                issue=agent_issue,
                asset=asset,
                family=family,
                run_id=run_id,
                sb_pub=sb_pub,
                emit_fn=emit_trace_demo,
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"Agentic planner raised, falling back to hybrid: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )

    enriched_pathways: list[RemediationPathway] = []

    if agent_result is not None:
        # --- AGENT SUCCESS PATH — no pattern used. Metadata + confidence from
        #     what the agent actually cited + what the verifier observed. ---
        llm_output, verification_report = agent_result
        for pathway in llm_output.pathways:
            pathway.validation_metadata = _agent_validation_metadata(pathway)
            confidence = compute_confidence_agentic(
                issue=issue,
                asset=asset,
                pathway=pathway,
                verification_report=verification_report,
            )
            pathway.confidence_score = confidence["score"]
            pathway.confidence_components = confidence["components"]
            enriched_pathways.append(pathway)
    else:
        # --- HYBRID fallback (pattern-based v1.4) ---
        # Per-issue prompt resolution — if a specialized prompt exists for this
        # finding's source+family, use it in the hybrid path too (not just agentic).
        # This makes the specialized trivy-image prompt work in BOTH paths.
        from .prompt_router import load_sa3_prompt as _router_load  # noqa: PLC0415

        issue_source = (issue.get("source") or "").strip()
        hybrid_prompt = _router_load(
            sb_pub, source=issue_source, family=family, default_version="v1.4"
        )
        hybrid_prompt_desc = f"{hybrid_prompt['agent']}@{hybrid_prompt['version']}"

        emit_trace_demo(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"Using hybrid planner with prompt: {hybrid_prompt_desc}",
        )
        params = hybrid_prompt.get("parameters") or {}
        base_temp = float(params.get("temperature", 0.3))
        max_tokens = int(params.get("max_tokens", 2500))
        primary_model = hybrid_prompt["model"]
        fallback_model = params.get("fallback_model", "gpt-4o")

        payload = {
            "issue": _issue_payload(issue, raw),
            "asset": asset,
            "pattern": _pattern_payload(pattern),
        }

        # Execution context — same injection as the agentic path. Tells the
        # generic prompt whether this is a container-image fix, host fix, or IaC.
        source = (issue.get("source") or "").lower()
        if "trivy-image" in source or "snyk-container" in source or "grype-image" in source:
            payload["execution_context"] = {
                "target_type": "container_image",
                "fix_approach": (
                    "Edit the Dockerfile to REMOVE the vulnerable package version pin entirely "
                    "(e.g. change 'openssl=1.1.1f-1ubuntu2' to just 'openssl'). "
                    "This lets apt-get install the latest available patched version at build time. "
                    "Do NOT specify a target version — just remove the =X.Y.Z pin. "
                    "Then rebuild with docker build --no-cache."
                ),
                "dockerfile_path": "/opt/vuln-labs/infra-lab/Dockerfile",
                "build_directory": "/opt/vuln-labs/infra-lab",
                "image_ref": "vuln-lab-image:latest",
                "rebuild_command": "cd /opt/vuln-labs/infra-lab && docker build --no-cache -t vuln-lab-image:latest .",
                "sed_pattern_example": "sed -i 's/<pkg>=<any_version>/<pkg>/' /opt/vuln-labs/infra-lab/Dockerfile",
                "rescan_command": "trivy image vuln-lab-image:latest --scanners vuln --severity HIGH,CRITICAL --format json",
                "rescan_target": "vuln-lab-image:latest (the rebuilt image, NOT ubuntu:20.04)",
                "validation_guidance": (
                    "IMPORTANT: The re-scan validation must check for the ABSENCE of the SPECIFIC CVE being fixed, "
                    "NOT for zero total vulnerabilities. The image has OTHER packages with their own CVEs — "
                    "fixing one CVE does not make the entire image vuln-free. "
                    "Use a command like: trivy image vuln-lab-image:latest --format json 2>&1 | grep -c '<CVE_ID>' || true "
                    "with expected='0' (zero occurrences of that specific CVE). "
                    "Do NOT use expected='\"Vulnerabilities\": []' — that will always fail on a multi-package image."
                ),
                "rescan_exit_code_note": (
                    "CRITICAL SHELL SEMANTICS: grep -c returns exit code 1 when match count is 0 "
                    "(i.e. when the CVE is GONE — the desired outcome). This will cause the execution "
                    "engine to treat a SUCCESSFUL fix as a failure. You MUST append '|| true' to any "
                    "grep -c command so the exit code is always 0. The validation engine checks the "
                    "OUTPUT value (expecting '0'), not the exit code. "
                    "Correct:  trivy image ... --format json 2>&1 | grep -c 'CVE-xxx' || true "
                    "Wrong:    trivy image ... --format json | grep -c 'CVE-xxx'"
                ),
                "remediation_steps_rules": (
                    "Do NOT put the re-scan/validation command in remediation_steps. "
                    "remediation_steps should contain ONLY actionable fix commands: "
                    "backup, sed edit, docker build, verify edit (grep Dockerfile). "
                    "The re-scan belongs EXCLUSIVELY in validation_tests with is_rescan=true."
                ),
                "prohibited_commands": [
                    "sudo reboot",
                    "apt-get install on host",
                    "edits to /etc/ or /usr/ on host",
                    "specifying a fixed version number in sed (just remove the pin)",
                    "expecting zero total vulnerabilities in validation (check only the specific CVE)",
                    "grep -c without || true (grep returns exit 1 on zero matches, which breaks execution)",
                ],
            }
        elif "trivy-os" in source or "tenable" in source or "qualys" in source:
            payload["execution_context"] = {
                "target_type": "host_os",
                "fix_approach": (
                    "Run apt-get update && apt-get install --only-upgrade <pkg> -y directly on the host. "
                    "NEVER pin to a specific version — public repos only serve the latest point release. "
                    "Always use: apt-get install --only-upgrade <pkg> -y (no =<version> suffix)."
                ),
                "verification_approach": (
                    "After upgrade, verify installed version is GREATER than the vulnerable version "
                    "using: dpkg -l <pkg> | grep <pkg>. Do NOT check for an exact target version."
                ),
                "rescan_command": "trivy rootfs / --scanners vuln --severity HIGH,CRITICAL --format json",
                "rescan_target": "/ (host root filesystem)",
                "remediation_steps_rules": (
                    "Do NOT put the re-scan in remediation_steps. Steps should be: "
                    "1. apt-get update, 2. apt-get install --only-upgrade <pkg> -y, "
                    "3. dpkg -l <pkg> (verify). Re-scan goes in validation_tests only."
                ),
                "reboot_policy": (
                    "No reboot unless CVE is in kernel (linux-image-*), libc6, or systemd."
                ),
                "prohibited_commands": [
                    "sudo reboot (unless kernel/libc/systemd CVE)",
                    "docker build",
                    "apt-get install <pkg>=<specific_version>",
                ],
            }

        llm_output = invoke_structured_with_retry(
            run_id=run_id,
            agent="sub-agent-3",
            schema=LLMRemediationOutput,
            messages=[
                SystemMessage(content=hybrid_prompt["prompt_text"]),
                HumanMessage(content=str(payload)),
            ],
            attempts=[
                (base_temp, primary_model, max_tokens),
                (0.5, primary_model, max_tokens + 500),
                (0.3, fallback_model, max_tokens + 1000),
            ],
            emit_fn=emit_trace_demo,
        )

        validation_meta = _validation_metadata_for(pattern)
        for pathway in llm_output.pathways:
            confidence = compute_confidence(
                issue=issue,
                asset=asset,
                pattern=pattern,
                pathway=pathway,
                affected_asset_count=1,
            )
            pathway.validation_metadata = validation_meta
            pathway.confidence_score = confidence["score"]
            pathway.confidence_components = confidence["components"]
            enriched_pathways.append(pathway)

    recommended_idx = max(
        range(len(enriched_pathways)),
        key=lambda i: enriched_pathways[i].confidence_score or 0,
    )
    recommended_score = enriched_pathways[recommended_idx].confidence_score or 0

    return RemediationPackage(
        issue_id=int(issue["id"]),
        family=family,
        finding=llm_output.finding,
        root_cause=llm_output.root_cause,
        impact=llm_output.impact,
        pathways=enriched_pathways,
        recommended_pathway_index=recommended_idx,
        approval_required=_derive_approval(recommended_score, issue.get("priority")),
    )


def _persist_to_demo(sb_demo: Any, pkg: RemediationPackage, run_id: str) -> int:
    """INSERT a RemediationPackage into demo.remediation_packages."""
    row = {
        "issue_id": pkg.issue_id,
        "family": pkg.family,
        "finding": pkg.finding,
        "root_cause": pkg.root_cause,
        "impact": pkg.impact,
        "pathways": [p.model_dump(mode="json") for p in pkg.pathways],
        "recommended_pathway_index": pkg.recommended_pathway_index,
        "approval_required": pkg.approval_required or "single_approver",
        "status": "awaiting_approval",
        "agent_run_id": run_id,
    }
    resp = sb_demo.table("remediation_packages").insert(row).execute()
    rows = resp.data or []
    return rows[0]["id"] if rows else 0
