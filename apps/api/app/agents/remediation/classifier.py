"""Finding -> Remediation Family classifier.

Deterministic rule-based mapping of an issue row to one of the 5 families in
the Phase-1 Remediation Pattern Library (migration 0036). Sub-Agent 3 calls
this BEFORE the LLM to look up the right pattern template.

Rules are intentionally simple and ordered so the most specific signal wins
first. For findings outside the Phase-1 scope, returns 'unknown' — the caller
should either skip or fall back to a generic prompt.

Families (keys in remediation_patterns):
  public_exposure        — Checkov S3 / cloud storage public access
  network_exposure       — Checkov SG open to 0.0.0.0/0 on admin port
  injection              — SAST/DAST findings (SQL/Command/Code/XSS injection)
  vulnerable_dependency  — SCA findings (Snyk, Dependabot, OSV, Trivy, Grype app pkgs)
  os_vulnerability       — Host scanners + Grype OS packages (apk/deb/rpm)
"""

from __future__ import annotations


Family = str  # one of the 5 above + 'unknown'


def classify_finding(issue: dict) -> Family:
    """Map an issue row to its remediation family. Pure function, no I/O.

    Expected keys on `issue`: source, title, cwe_id, runtime_purl.
    Missing keys are treated as empty string. Never raises.
    """
    source = (issue.get("source") or "").lower()
    title = (issue.get("title") or "").lower()
    cwe = (issue.get("cwe_id") or "").upper()
    purl = (issue.get("runtime_purl") or "").lower()

    # 1) Checkov + public storage -> public_exposure
    if source.startswith("checkov"):
        if (
            "s3" in title or "bucket" in title or "storage" in title or "blob" in title
        ) and "public" in title:
            return "public_exposure"
        if (
            "security group" in title
            or "security_group" in title
            or "0.0.0.0/0" in title
            or " ssh" in title
        ):
            return "network_exposure"

    # 2) SCA tools -> vulnerable_dependency (regardless of title keywords)
    if source in ("snyk-appsec", "dependabot", "osv", "trivy-cloud"):
        return "vulnerable_dependency"

    # 3) Grype -> split by ecosystem
    if source == "grype":
        if purl.startswith(("pkg:apk", "pkg:deb", "pkg:rpm")):
            return "os_vulnerability"
        if purl.startswith(
            ("pkg:npm", "pkg:pypi", "pkg:maven", "pkg:gem", "pkg:cargo", "pkg:nuget", "pkg:golang")
        ):
            return "vulnerable_dependency"
        return "os_vulnerability"  # most grype findings are OS-level

    # 4) Host scanners -> os_vulnerability
    if source in ("tenable-nessus-vuln", "qualys-vmdr-vuln", "tenable", "qualys"):
        return "os_vulnerability"

    # 5) Injection CWEs / SAST / DAST -> injection
    INJECTION_CWES = {
        "CWE-89",  # SQL Injection
        "CWE-78",  # OS Command Injection
        "CWE-94",  # Code Injection
        "CWE-95",  # eval Injection
        "CWE-77",  # Generic Command Injection
        "CWE-90",  # LDAP Injection
        "CWE-91",  # XML Injection
        "CWE-79",  # XSS
        "CWE-74",  # Generic Injection
    }
    if cwe in INJECTION_CWES:
        return "injection"

    if any(
        kw in title
        for kw in (
            "sql injection",
            "command injection",
            "code injection",
            "ldap injection",
            "xml injection",
            "template injection",
            "xss",
            "cross-site scripting",
            "cross site scripting",
        )
    ):
        return "injection"

    if source in ("sonarqube-appsec", "semgrep-appsec", "burp-suite"):
        return "injection"  # default class for these tools in Phase-1 scope

    return "unknown"
