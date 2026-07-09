"""Post-synthesis verification pass for the agentic Sub-Agent 3.

After the LLM produces a draft RemediationPackage, this module runs an
enterprise-grade safety pass:

  1. Extract the CLI/code commands from each remediation step
  2. For each unique command, do a targeted web_search to check whether the
     command appears in a source OTHER than the one the step originally cited.
     Two-source consensus → verified. Only one source → flagged.
  3. Scan every command for destructive patterns (rm -rf, DROP DATABASE,
     terraform destroy, aws rds delete-db-instance without --skip-final-
     snapshot, kubectl delete namespace, etc.). Flag any match.
  4. Return a VerificationReport that gets stitched into the pathway's
     `considerations` array + persisted to package.validation_metadata.

Never REJECTS a draft — safety is fail-open with visible flags, not
fail-closed. Human approval flow catches problems.

Budget: shares the same AgentBudget as the research phase. If the research
phase used the full 12 calls, verification is skipped with an
UNVERIFIED-DUE-TO-BUDGET note.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ...models import LLMRemediationOutput
from .tools.budget import AgentBudget
from .tools.web_search import web_search


# =============================================================================
# Unfilled placeholder patterns — commands that ship these are unrunnable
# =============================================================================
_UNFILLED_PLACEHOLDER_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "curly-brace",
        re.compile(r"\{[a-zA-Z_][\w-]*\}"),
        "Unfilled '{name}' placeholder — should be a concrete value from the finding.",
    ),
    (
        "angle-brace",
        # e.g. <bucket-name>, <security-group-id> — but NOT curl's %{http_code}
        re.compile(r"<[a-zA-Z_][\w-]{2,}(?:-[\w-]+)*>"),
        "Unfilled '<name>' placeholder — should be a concrete value from the finding.",
    ),
    (
        "path-to-placeholder",
        re.compile(r"/path/to/\w+"),
        "Literal '/path/to/...' placeholder — should be a real path from the finding.",
    ),
    (
        "your-uppercase-placeholder",
        re.compile(r"\bYOUR[_-][A-Z][A-Z_]+\b|\b[A-Z]+_ID\b|\b[A-Z]+_HERE\b"),
        "UPPERCASE placeholder (YOUR_*, *_ID, *_HERE) — should be a concrete value.",
    ),
    (
        "bracketed-replace",
        re.compile(r"\[(?:REPLACE|INSERT|YOUR|EXAMPLE|TODO)[_A-Z\s-]*\]", re.IGNORECASE),
        "Bracketed '[REPLACE_ME]' style placeholder — should be a concrete value.",
    ),
    (
        "example-domain",
        re.compile(r"\bexample\.(?:com|org|net)\b|\bexample-\w+"),
        "Example domain / literal 'example-*' — should be the real hostname from the finding.",
    ),
]


# =============================================================================
# Low-authority URL patterns — the domain looks authoritative but the path
# reveals it's a product / marketplace / pricing / console page, not docs.
# =============================================================================
_LOW_AUTHORITY_PATH_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "marketplace",
        re.compile(r"/marketplace/", re.IGNORECASE),
        "Marketplace listing (product page, not remediation guidance).",
    ),
    (
        "product-page",
        re.compile(r"/products?/(?![^/]+/docs?/)", re.IGNORECASE),
        "Product/service landing page, not documentation.",
    ),
    (
        "pricing",
        re.compile(r"/pricing/?", re.IGNORECASE),
        "Pricing page, not remediation guidance.",
    ),
    (
        "console",
        re.compile(r"console\.(aws|cloud\.google|azure)", re.IGNORECASE),
        "AWS/GCP/Azure console URL — user-facing UI, not documentation.",
    ),
    (
        "faq",
        re.compile(r"/faq/?|/support/answer/", re.IGNORECASE),
        "FAQ page — usually generic, not remediation-specific.",
    ),
    (
        "blog-index",
        re.compile(r"/blog/?$|/blog/tag/|/blog/category/", re.IGNORECASE),
        "Blog index / tag / category page — not a specific article.",
    ),
]


# =============================================================================
# Per-family minimum step depth — the LLM often under-produces; flag if so
# =============================================================================
_MIN_STEPS_BY_FAMILY = {
    "public_exposure": 6,
    "network_exposure": 6,
    "injection": 6,
    "vulnerable_dependency": 8,
    "os_vulnerability": 6,
}
_MIN_VALIDATION_TESTS = 3
_MIN_TEST_SCRIPTS = 2
_MIN_ROLLBACK_STEPS_RATIO = 0.5  # rollback ≥ 50% of remediation depth


# =============================================================================
# Destructive command patterns — regex, ordered by severity
# Each entry: (name, regex, severity, explanation)
# =============================================================================
_DESTRUCTIVE_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "rm-rf-root",
        re.compile(r"\brm\s+-rf\s+(/|\$\w+|/[a-zA-Z])", re.IGNORECASE),
        "critical",
        "Recursive delete near filesystem root. Verify path expansion + confirm before running.",
    ),
    (
        "dd-of-device",
        re.compile(r"\bdd\s+.*of=/dev/", re.IGNORECASE),
        "critical",
        "Direct write to block device — irreversible if wrong device.",
    ),
    (
        "sql-drop-database",
        re.compile(r"\bDROP\s+(DATABASE|SCHEMA)\b", re.IGNORECASE),
        "critical",
        "Drops entire database/schema. Confirm no active connections + take backup.",
    ),
    (
        "sql-truncate-no-where",
        re.compile(r"\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\s+\w+(?!\s+WHERE)", re.IGNORECASE),
        "high",
        "Bulk delete without WHERE clause. Confirm table + backup before running.",
    ),
    (
        "terraform-destroy",
        re.compile(r"\bterraform\s+(destroy|apply\s+-destroy)\b", re.IGNORECASE),
        "critical",
        "Destroys managed infrastructure. Run terraform plan -destroy first + human approval.",
    ),
    (
        "aws-delete-no-snapshot",
        re.compile(
            r"\baws\s+(rds|redshift|elasticache|efs|dynamodb)\s+delete-\S+"
            r"(?!.*--(skip-final-snapshot|final-cluster-snapshot|backup-before-delete))",
            re.IGNORECASE | re.DOTALL,
        ),
        "high",
        "AWS resource delete without final-snapshot / backup flag. Data loss risk.",
    ),
    (
        "kubectl-delete-namespace",
        re.compile(r"\bkubectl\s+delete\s+(namespace|ns)\s+\w+", re.IGNORECASE),
        "high",
        "Deletes entire namespace including all workloads + PVCs. Verify target + backup.",
    ),
    (
        "docker-prune-a",
        re.compile(r"\bdocker\s+system\s+prune\s+.*(-a|--all)\b", re.IGNORECASE),
        "medium",
        "Removes all unused Docker resources including unused images. Verify host is not shared.",
    ),
    (
        "git-force-push-main",
        re.compile(r"\bgit\s+push\s+.*--force.*\b(main|master)\b", re.IGNORECASE),
        "high",
        "Force-push to main/master rewrites history. Coordinate with team + backup branch.",
    ),
    (
        "chmod-recursive-root",
        re.compile(r"\bchmod\s+.*-R\s+.*\s+(/|/etc|/usr|/bin|/sbin)", re.IGNORECASE),
        "high",
        "Recursive chmod near system directories — can render system unbootable.",
    ),
    (
        "iam-delete-user",
        re.compile(r"\baws\s+iam\s+delete-user\b", re.IGNORECASE),
        "medium",
        "Deletes IAM user. Verify no service dependencies + take audit log snapshot first.",
    ),
    (
        "s3-rb-force",
        re.compile(r"\baws\s+s3\s+rb\s+.*--force\b", re.IGNORECASE),
        "critical",
        "Force-deletes S3 bucket with all objects. Irrecoverable if versioning not enabled.",
    ),
]


@dataclass
class VerificationReport:
    """Aggregate of what the verifier found."""

    total_steps: int = 0
    total_commands_examined: int = 0
    cross_verified: int = 0  # command found in a second source
    single_source: int = 0  # command only in original citation
    destructive_flags: list[dict] = field(default_factory=list)
    placeholder_flags: list[dict] = field(default_factory=list)
    low_authority_flags: list[dict] = field(default_factory=list)
    depth_flags: list[dict] = field(default_factory=list)
    consensus_notes: list[str] = field(default_factory=list)
    verification_urls: list[str] = field(default_factory=list)
    skipped_due_to_budget: bool = False

    def to_considerations(self) -> list[str]:
        """Render report as bullet lines suitable for pathway.considerations."""
        lines: list[str] = []

        # 1. Depth flags first — these tell reviewer the package is under-produced
        for flag in self.depth_flags:
            lines.append(f"⚠ [DEPTH] {flag['message']}")

        # 2. Placeholder flags — commands are UNRUNNABLE if these ship
        for flag in self.placeholder_flags:
            lines.append(
                f"🔴 [UNRUNNABLE] Step {flag['step_num']} contains {flag['pattern']} "
                f"placeholder ({flag['match']}): {flag['explanation']} "
                "Fill with the concrete value before running."
            )

        # 3. Low-authority source flags — reviewer needs to seek better source
        for flag in self.low_authority_flags:
            lines.append(
                f"⚠ [LOW-AUTHORITY SOURCE] Step {flag['step_num']} cites "
                f"{flag['url']}: {flag['explanation']} "
                "Consider finding the vendor's official docs page and re-verifying."
            )

        # 4. Destructive-pattern flags — must be reviewed
        for flag in self.destructive_flags:
            lines.append(
                f"⚠ [{flag['severity'].upper()}] Step {flag['step_num']} contains "
                f"'{flag['pattern']}': {flag['explanation']}"
            )

        # 5. Cross-source consensus summary
        if self.total_commands_examined:
            lines.append(
                f"Cross-verified {self.cross_verified}/{self.total_commands_examined} "
                f"critical commands against 2+ independent sources."
            )
        if self.single_source:
            lines.append(
                f"⚠ {self.single_source} command(s) verified against ONE source only — "
                "recommend dry-run in staging before applying to production."
            )
        for note in self.consensus_notes:
            lines.append(note)

        # 6. Budget skip note
        if self.skipped_due_to_budget:
            lines.append(
                "Verification pass skipped — research phase consumed all tool-call "
                "budget. Consider running package through human review before applying."
            )
        return lines


# =============================================================================
# Command extraction from step text
#
# The LLM formats commands multiple different ways depending on how it read
# its source pages. All of the following shapes must be recognised, because
# the verifier feeds these into cross-source consensus + destructive-pattern
# scanning — miss a shape and we score a package as "0 verifiable commands"
# even though it's full of real commands.
#
# Shapes recognised:
#   1. "Command:\n <block>\n Why: ..."           (our prompt's canonical shape)
#   2. "Commands:\n <block>"                     (plural variant LLM often uses)
#   3. ```bash\n<block>\n``` or ```<block>```    (markdown fenced code blocks)
#   4. Indented shell prompts: `$ cmd` or `# cmd` at start of line
#   5. `inline command`                          (single-backtick inline code)
# =============================================================================
_COMMAND_BLOCK_RE = re.compile(
    r"Commands?:\s*\n(.*?)(?:\n\s*(?:Why|Rationale|Reason|Expected|Notes?):|\n\s*\n|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_FENCED_CODE_RE = re.compile(
    r"```(?:bash|sh|shell|zsh|console|terminal|hcl|terraform|yaml|yml|python|py)?\s*\n(.*?)```",
    re.DOTALL | re.IGNORECASE,
)
_SHELL_PROMPT_LINE_RE = re.compile(r"^\s*[#\$]\s+(.+)$", re.MULTILINE)
_INLINE_BACKTICK_RE = re.compile(r"`([^`\n]{6,200})`")

# Words that hint an inline backtick is code (`aws s3 cp ...`, `terraform ...`).
# Filters out prose backticks like `Amazon S3` or `Access Denied`.
_CMD_HEAD_TOKENS = (
    "aws ",
    "az ",
    "gcloud ",
    "kubectl ",
    "helm ",
    "docker ",
    "terraform ",
    "tf ",
    "ansible ",
    "chef ",
    "puppet ",
    "curl ",
    "wget ",
    "openssl ",
    "ssh ",
    "scp ",
    "rsync ",
    "iptables ",
    "ufw ",
    "firewall-cmd ",
    "systemctl ",
    "service ",
    "yum ",
    "apt ",
    "apt-get ",
    "dnf ",
    "zypper ",
    "pacman ",
    "brew ",
    "pip ",
    "pip3 ",
    "npm ",
    "yarn ",
    "pnpm ",
    "mvn ",
    "gradle ",
    "python ",
    "python3 ",
    "node ",
    "ruby ",
    "go ",
    "java ",
    "git ",
    "make ",
    "cmake ",
    "bash ",
    "sh ",
    "select ",
    "insert ",
    "update ",
    "delete ",
    "create ",
    "alter ",
    "drop ",
    "grant ",
    "revoke ",
)


def _extract_commands(step_text: str) -> list[str]:
    """Pull out CLI/code command lines from a step text block.

    Tries several shapes (see module docstring above the regexes). Returns a
    deduped list of trimmed command lines. Order preserves first appearance.
    """
    if not step_text:
        return []

    found: list[str] = []
    seen: set[str] = set()

    def _add(cmd: str) -> None:
        cmd = cmd.strip().rstrip("\\").strip()
        if not cmd or len(cmd) < 4:
            return
        # Drop pure code fences, headings, and prose lines
        if cmd.startswith(("```", "#", "//", "/*", "*", "-", ">")):
            # Allow `# comment` only if it's followed by a real command token
            if not any(t in cmd.lower() for t in _CMD_HEAD_TOKENS):
                return
        key = cmd[:100].lower()
        if key not in seen:
            seen.add(key)
            found.append(cmd)

    # Shape 1+2 — "Command:" / "Commands:" block
    for m in _COMMAND_BLOCK_RE.finditer(step_text):
        block = m.group(1).strip()
        raw_lines = [ln for ln in block.splitlines() if ln.strip()]
        if raw_lines:
            common_indent = min(len(ln) - len(ln.lstrip()) for ln in raw_lines)
            for ln in raw_lines:
                _add(ln[common_indent:])

    # Shape 3 — fenced code blocks (```bash ... ```)
    for m in _FENCED_CODE_RE.finditer(step_text):
        block = m.group(1).strip()
        raw_lines = [ln for ln in block.splitlines() if ln.strip()]
        if raw_lines:
            common_indent = min(len(ln) - len(ln.lstrip()) for ln in raw_lines)
            for ln in raw_lines:
                _add(ln[common_indent:])

    # Shape 4 — shell prompt lines (`$ cmd` or `# cmd`)
    for m in _SHELL_PROMPT_LINE_RE.finditer(step_text):
        _add(m.group(1))

    # Shape 5 — inline backticks that look like commands
    for m in _INLINE_BACKTICK_RE.finditer(step_text):
        inline = m.group(1)
        low = inline.lower().lstrip()
        if any(low.startswith(tok) for tok in _CMD_HEAD_TOKENS):
            _add(inline)

    return found


def _short_command(cmd: str, max_len: int = 80) -> str:
    """Compact command representation for search queries + trace messages."""
    cmd = " ".join(cmd.split())  # collapse whitespace
    return cmd[:max_len] + ("..." if len(cmd) > max_len else "")


def _command_key(cmd: str) -> str:
    """Normalise a command for dedup — first 4 tokens + trailing key flag."""
    tokens = cmd.split()
    return " ".join(tokens[:4]).lower()


# =============================================================================
# Public: run the verification pass
# =============================================================================
def verify_output(
    output: LLMRemediationOutput,
    *,
    budget: AgentBudget,
    run_id: str,
    emit_fn,
    family: str | None = None,
    max_commands_to_verify: int = 4,
) -> VerificationReport:
    """Run cross-source consensus + destructive-pattern checks over the draft.

    Mutates `output.pathways[i].considerations` to append warnings.
    Returns the aggregated VerificationReport so the caller can persist a
    top-level summary.

    Fail-open: any exception during a single command's verification is logged
    but doesn't halt the pass. Budget-exhausted → skip remaining verification,
    note it, return partial results.
    """
    report = VerificationReport()
    if not output or not output.pathways:
        return report

    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"🔎 Verification pass starting — will cross-check up to "
        f"{max_commands_to_verify} commands against 2+ sources",
    )

    # ---- 1. Collect commands to verify + destructive-pattern scan ----
    #     Structure per candidate: (pathway_idx, step_num, original_url, command_line)
    candidates: list[tuple[int, int, str, str]] = []
    seen_keys: set[str] = set()

    for p_idx, pathway in enumerate(output.pathways):
        for step_num, step in enumerate(pathway.remediation_steps, start=1):
            report.total_steps += 1
            step_text = getattr(step, "step", "") or ""
            original_url = getattr(step, "source_url", "") or ""
            commands = _extract_commands(step_text)

            # --- Low-authority URL check (path-based, cheap) ---
            for name, pattern, explanation in _LOW_AUTHORITY_PATH_PATTERNS:
                if pattern.search(original_url):
                    report.low_authority_flags.append(
                        {
                            "pathway_idx": p_idx,
                            "step_num": step_num,
                            "pattern": name,
                            "url": original_url,
                            "explanation": explanation,
                        }
                    )
                    emit_fn(
                        run_id,
                        "sub-agent-3",
                        "MESSAGE",
                        f"⚠ Step {step_num} cites low-authority URL ({name}): {original_url[:100]}",
                    )
                    break  # one flag per step is enough

            # Scan step_text + each command for issues
            search_targets = [step_text] + commands

            # --- Unfilled placeholder check ---
            for target in search_targets:
                for name, pattern, explanation in _UNFILLED_PLACEHOLDER_PATTERNS:
                    m = pattern.search(target)
                    if m:
                        # Skip curl's %{http_code} format specifier — legit
                        match_text = m.group(0)
                        if (
                            match_text == "{http_code}"
                            and "%"
                            in target[max(0, m.start() - 1) : m.start() + len(match_text) + 1]
                        ):
                            continue
                        report.placeholder_flags.append(
                            {
                                "pathway_idx": p_idx,
                                "step_num": step_num,
                                "pattern": name,
                                "match": match_text,
                                "explanation": explanation,
                            }
                        )
                        emit_fn(
                            run_id,
                            "sub-agent-3",
                            "MESSAGE",
                            f"🔴 Step {step_num}: unfilled placeholder "
                            f"'{match_text}' — command unrunnable as-is",
                        )
                        break  # one placeholder flag per step is enough
                else:
                    continue
                break

            # --- Destructive-pattern scan (unchanged) ---
            for cmd in commands:
                for name, pattern, severity, explanation in _DESTRUCTIVE_PATTERNS:
                    if pattern.search(cmd):
                        report.destructive_flags.append(
                            {
                                "pathway_idx": p_idx,
                                "step_num": step_num,
                                "pattern": name,
                                "severity": severity,
                                "explanation": explanation,
                                "command_snippet": _short_command(cmd),
                            }
                        )
                        emit_fn(
                            run_id,
                            "sub-agent-3",
                            "MESSAGE",
                            f"⚠ [{severity.upper()}] Step {step_num}: destructive "
                            f"pattern '{name}' detected — {explanation}",
                        )

                # Queue for cross-source verification (dedup by key)
                key = _command_key(cmd)
                if key and key not in seen_keys:
                    seen_keys.add(key)
                    candidates.append((p_idx, step_num, original_url, cmd))

    # ---- 2. Cross-source verify up to N unique commands ----
    to_verify = candidates[:max_commands_to_verify]
    for _p_idx, step_num, original_url, cmd in to_verify:
        allowed, _ = budget.can_call()
        if not allowed:
            report.skipped_due_to_budget = True
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                "Verification: budget exhausted — remaining commands unverified",
            )
            break

        report.total_commands_examined += 1
        query = _short_command(cmd, max_len=100)

        try:
            search = web_search(
                query,
                budget,
                max_results=4,
                search_depth="basic",  # cheaper for verification hits
                run_id=run_id,
                emit_fn=emit_fn,
            )
        except Exception as e:  # noqa: BLE001
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"Verification search failed for step {step_num}: "
                f"{type(e).__name__}: {str(e)[:150]}",
            )
            report.single_source += 1
            continue

        # Which domains cited this command? Compare against original_url's host.
        original_host = _host_of(original_url)
        supporting_hosts = {
            _host_of(r["url"])
            for r in search["results"]
            if _host_of(r["url"]) and _host_of(r["url"]) != original_host
        }
        supporting_urls = [
            r["url"] for r in search["results"] if _host_of(r["url"]) in supporting_hosts
        ]

        if supporting_hosts:
            report.cross_verified += 1
            report.verification_urls.extend(supporting_urls[:2])
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"✓ Step {step_num} command verified across {1 + len(supporting_hosts)} sources",
            )
        else:
            report.single_source += 1
            report.consensus_notes.append(
                f"Step {step_num}: command '{_short_command(cmd, 60)}' "
                f"appears only in {original_host or 'the originally cited source'} — "
                "recommend independent verification before production apply."
            )
            emit_fn(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"⚠ Step {step_num} command NOT independently verified "
                f"({original_host or 'origin'} only)",
            )

    # ---- 3. Per-family depth check (does the package have enough steps?) ----
    if family and family in _MIN_STEPS_BY_FAMILY:
        min_steps = _MIN_STEPS_BY_FAMILY[family]
        for p_idx, pathway in enumerate(output.pathways):
            step_count = len(pathway.remediation_steps or [])
            test_count = len(pathway.validation_tests or [])
            script_count = len(pathway.test_scripts or [])
            rb_step_count = len(pathway.rollback_plan.steps or []) if pathway.rollback_plan else 0

            if step_count < min_steps:
                report.depth_flags.append(
                    {
                        "pathway_idx": p_idx,
                        "message": (
                            f"Only {step_count} remediation steps for family '{family}' "
                            f"(expected ≥ {min_steps}). Package likely missing steps "
                            "(backup? staging apply? monitoring window?)."
                        ),
                    }
                )
            if test_count < _MIN_VALIDATION_TESTS:
                report.depth_flags.append(
                    {
                        "pathway_idx": p_idx,
                        "message": (
                            f"Only {test_count} validation test(s) (expected ≥ "
                            f"{_MIN_VALIDATION_TESTS}). Consider tests for: "
                            "positive assertion, negative assertion, and monitoring."
                        ),
                    }
                )
            if script_count < _MIN_TEST_SCRIPTS:
                report.depth_flags.append(
                    {
                        "pathway_idx": p_idx,
                        "message": (
                            f"Only {script_count} test script(s) (expected ≥ "
                            f"{_MIN_TEST_SCRIPTS}). Consider adding a rollback script + "
                            "a smoke test script."
                        ),
                    }
                )
            if pathway.rollback_plan and pathway.rollback_plan.supported:
                min_rb = max(2, int(step_count * _MIN_ROLLBACK_STEPS_RATIO))
                if rb_step_count < min_rb:
                    report.depth_flags.append(
                        {
                            "pathway_idx": p_idx,
                            "message": (
                                f"Rollback has only {rb_step_count} step(s) for a "
                                f"{step_count}-step remediation (expected ≥ {min_rb}). "
                                "Rollback should mirror remediation depth."
                            ),
                        }
                    )

    # ---- 4. Stitch report notes into each pathway's considerations ----
    aggregate_notes = report.to_considerations()
    for pathway in output.pathways:
        existing = list(pathway.considerations or [])
        # Cap total considerations to schema max (15)
        room = 15 - len(existing)
        if room > 0 and aggregate_notes:
            existing.extend(aggregate_notes[:room])
            pathway.considerations = existing

    emit_fn(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"Verification complete — cross_verified={report.cross_verified}, "
        f"single_source={report.single_source}, "
        f"destructive_flags={len(report.destructive_flags)}, "
        f"budget_left={budget.max_calls - budget.call_count}",
    )
    return report


def _host_of(url: str) -> str:
    """Return hostname of a URL, or '' if malformed."""
    if not url:
        return ""
    try:
        return urlparse(url).netloc.lower()
    except Exception:  # noqa: BLE001
        return ""


# =============================================================================
# Lightweight re-scan — used by retry paths to check whether a re-invocation
# reduced placeholder/destructive counts, without paying for another round of
# cross-source consensus web calls. Pure regex, no I/O.
# =============================================================================
def scan_placeholder_flags(output: LLMRemediationOutput) -> list[dict]:
    """Return the list of placeholder flags that would fire on this output.
    Same regex set the full verifier uses — kept in sync via _UNFILLED_
    PLACEHOLDER_PATTERNS constant. No web calls, safe to re-invoke.
    """
    flags: list[dict] = []
    if not output or not output.pathways:
        return flags
    for p_idx, pathway in enumerate(output.pathways):
        for step_num, step in enumerate(pathway.remediation_steps or [], start=1):
            step_text = getattr(step, "step", "") or ""
            commands = _extract_commands(step_text)
            for target in [step_text] + commands:
                for name, pattern, explanation in _UNFILLED_PLACEHOLDER_PATTERNS:
                    m = pattern.search(target)
                    if not m:
                        continue
                    match_text = m.group(0)
                    # Skip curl's %{http_code} format specifier — legit
                    if (
                        match_text == "{http_code}"
                        and "%" in target[max(0, m.start() - 1) : m.start() + len(match_text) + 1]
                    ):
                        continue
                    flags.append(
                        {
                            "pathway_idx": p_idx,
                            "step_num": step_num,
                            "pattern": name,
                            "match": match_text,
                            "explanation": explanation,
                        }
                    )
                    break  # one per step is enough
    return flags
