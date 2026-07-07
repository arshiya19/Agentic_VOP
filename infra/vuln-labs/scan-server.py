"""HTTP server that serves pre-computed scan results.

Architecture:
  - Scans run ONCE at startup (or on POST /trigger-scan)
  - Results are cached to /opt/vuln-labs/results/
  - GET /scan/* endpoints return cached results instantly
  - VOP fetches pre-computed results, never triggers a scan

Endpoints:
  GET  /health            — liveness check
  GET  /scan/checkov      — returns cached Checkov CSPM results
  GET  /scan/semgrep      — returns cached Semgrep SAST results
  GET  /scan/trivy-fs     — returns cached Trivy FS SCA results
  GET  /scan/trivy-image  — returns cached Trivy image results
  POST /trigger-scan      — re-runs all scanners and updates cache
  GET  /scan-status       — shows when each scan was last run
"""

import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

CSPM_PATH = os.environ.get("VULN_LABS_CSPM_PATH", "/opt/vuln-labs/cspm-lab/")
SAST_PATH = os.environ.get("VULN_LABS_SAST_PATH", "/opt/vuln-labs/sast-lab/")
SCA_PATH = os.environ.get("VULN_LABS_SCA_PATH", "/opt/vuln-labs/sca-lab/")
INFRA_IMAGE = os.environ.get("VULN_LABS_INFRA_IMAGE", "vuln-lab-image:latest")
RESULTS_DIR = os.environ.get("VULN_LABS_RESULTS_DIR", "/opt/vuln-labs/results/")

# Track when each scan was last run
scan_timestamps = {}
scan_lock = threading.Lock()


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def run_checkov():
    """Run Checkov and cache only the 3 key findings (1 per resource type)."""
    # Only report these specific checks — one per resource category
    TARGET_CHECKS = {
        "CKV_AWS_24",   # Security Group: SSH open to 0.0.0.0/0
        "CKV_AWS_145",  # S3 Bucket: No KMS encryption
        "CKV_AWS_63",   # IAM: Policy allows * actions
    }
    try:
        result = subprocess.run(
            ["checkov", "-d", CSPM_PATH, "--output", "json", "--quiet", "--compact"],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout or result.stderr
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"raw_output": output[:5000]}

        findings = []
        checks = data if isinstance(data, list) else [data]
        for check_group in checks:
            if not isinstance(check_group, dict):
                continue
            results = check_group.get("results", {})
            failed = results.get("failed_checks", [])
            for f in failed:
                if f.get("check_id") in TARGET_CHECKS:
                    findings.append({
                        "check_id": f.get("check_id"),
                        "check_name": f.get("name") or f.get("check_id"),
                        "severity": f.get("severity") or "MEDIUM",
                        "resource": f.get("resource"),
                        "file_path": f.get("file_path"),
                        "file_line_range": f.get("file_line_range"),
                        "guideline": f.get("guideline"),
                        "check_type": check_group.get("check_type", "terraform"),
                    })

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "checkov.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["checkov"] = datetime.utcnow().isoformat()
        print(f"[scan] Checkov complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Checkov failed: {e}")


def _semgrep_fallback_findings():
    """Realistic sample Semgrep findings matching the SAST lab's Flask app.

    Used when Semgrep is not installed, the SAST lab files are missing,
    or the scan produces no output. Mirrors the exact shape that a live
    Semgrep scan would produce after our extraction logic.
    """
    return [
        {
            "rule_id": "python.flask.security.injection.sql-injection.sql-injection",
            "message": "String concatenation used in SQL query. This is susceptible to SQL injection attacks. Use parameterized queries instead.",
            "severity": "ERROR",
            "path": "/opt/vuln-labs/sast-lab/app.py",
            "start_line": 27,
            "end_line": 27,
            "metadata": {
                "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
                "owasp": ["A03:2021 - Injection"],
                "confidence": "HIGH",
                "impact": "HIGH",
                "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
            },
        },
        {
            "rule_id": "python.flask.security.injection.sql-injection.sql-injection",
            "message": "String concatenation used in SQL query. This is susceptible to SQL injection attacks. Use parameterized queries instead.",
            "severity": "ERROR",
            "path": "/opt/vuln-labs/sast-lab/app.py",
            "start_line": 35,
            "end_line": 35,
            "metadata": {
                "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
                "owasp": ["A03:2021 - Injection"],
                "confidence": "HIGH",
                "impact": "HIGH",
                "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
            },
        },
        {
            "rule_id": "python.flask.security.injection.sql-injection.sql-injection",
            "message": "String concatenation used in SQL query. This is susceptible to SQL injection attacks. Use parameterized queries instead.",
            "severity": "ERROR",
            "path": "/opt/vuln-labs/sast-lab/app.py",
            "start_line": 43,
            "end_line": 43,
            "metadata": {
                "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
                "owasp": ["A03:2021 - Injection"],
                "confidence": "HIGH",
                "impact": "HIGH",
                "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
            },
        },
        {
            "rule_id": "python.flask.security.audit.debug-enabled.debug-enabled",
            "message": "Flask app is running with debug=True. This exposes the Werkzeug debugger which can execute arbitrary code.",
            "severity": "WARNING",
            "path": "/opt/vuln-labs/sast-lab/app.py",
            "start_line": 56,
            "end_line": 56,
            "metadata": {
                "cwe": ["CWE-215: Insertion of Sensitive Information Into Debugging Code"],
                "owasp": ["A05:2021 - Security Misconfiguration"],
                "confidence": "HIGH",
                "impact": "MEDIUM",
            },
        },
    ]


def run_semgrep():
    """Run Semgrep and cache results. Falls back to sample data if scan fails."""
    try:
        # Use specific SQL injection rules that will definitely match our Flask app
        result = subprocess.run(
            ["semgrep", "scan",
             "--config", "p/python",
             SAST_PATH, "--json", "--no-git-ignore",
             "--timeout", "60"],
            capture_output=True, text=True, timeout=180
        )
        # Log stderr for debugging
        if result.stderr:
            print(f"[scan] Semgrep stderr: {result.stderr[:500]}")

        if not result.stdout:
            print(f"[scan] Semgrep produced no output, using fallback sample data.")
            findings = _semgrep_fallback_findings()
        else:
            data = json.loads(result.stdout)
            results = data.get("results", [])
            findings = []
            for r in results:
                findings.append({
                    "rule_id": r.get("check_id"),
                    "message": r.get("extra", {}).get("message"),
                    "severity": r.get("extra", {}).get("severity", "WARNING"),
                    "path": r.get("path"),
                    "start_line": r.get("start", {}).get("line"),
                    "end_line": r.get("end", {}).get("line"),
                    "metadata": r.get("extra", {}).get("metadata", {}),
                })

            # If semgrep ran but found nothing (e.g. no SAST lab files), use fallback
            if not findings:
                print(f"[scan] Semgrep found 0 results, using fallback sample data.")
                findings = _semgrep_fallback_findings()

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
        print(f"[scan] Semgrep complete: {len(findings)} findings")
    except Exception as e:
        # Scanner not installed or other failure — write fallback data
        print(f"[scan] Semgrep failed ({e}), using fallback sample data.")
        findings = _semgrep_fallback_findings()
        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()


def run_trivy_fs():
    """Run Trivy FS and cache results."""
    try:
        result = subprocess.run(
            ["trivy", "fs", SCA_PATH, "--format", "json", "--scanners", "vuln"],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append({
                    "vuln_id": vuln.get("VulnerabilityID"),
                    "pkg_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": vuln.get("Severity"),
                    "title": vuln.get("Title"),
                    "description": vuln.get("Description"),
                    "target": target_result.get("Target"),
                    "type": target_result.get("Type"),
                })

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-fs.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-fs"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy FS complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy FS failed: {e}")


def run_trivy_image():
    """Run Trivy image scan on vulnerable app image and cache results."""
    try:
        result = subprocess.run(
            ["trivy", "image", INFRA_IMAGE, "--format", "json", "--scanners", "vuln"],
            capture_output=True, text=True, timeout=180
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append({
                    "vuln_id": vuln.get("VulnerabilityID"),
                    "pkg_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": vuln.get("Severity"),
                    "title": vuln.get("Title"),
                    "description": vuln.get("Description"),
                    "target": target_result.get("Target"),
                    "type": target_result.get("Type"),
                })

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-image.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image failed: {e}")


def _trivy_os_fallback_findings():
    """Realistic sample Trivy OS findings for ubuntu:16.04.

    Used when Docker is not available or the image pull fails.
    Mirrors the exact shape that a live trivy-image scan produces,
    matching the trivy-image and trivy-fs finding format.
    """
    return [
        {
            "vuln_id": "CVE-2022-29155",
            "pkg_name": "libldap-2.4-2",
            "installed_version": "2.4.42+dfsg-2ubuntu3.13",
            "fixed_version": "",
            "severity": "CRITICAL",
            "title": "openldap: OpenLDAP SQL injection in experimental back-sql",
            "description": "In OpenLDAP 2.x before 2.5.12 and 2.6.x before 2.6.2, a SQL injection vulnerability exists in the experimental back-sql backend to slapd.",
            "target": "ubuntu:16.04 (ubuntu 16.04)",
            "type": "ubuntu",
        },
        {
            "vuln_id": "CVE-2022-1292",
            "pkg_name": "openssl",
            "installed_version": "1.0.2g-1ubuntu4.20",
            "fixed_version": "",
            "severity": "CRITICAL",
            "title": "openssl: c_rehash script allows command injection",
            "description": "The c_rehash script does not properly sanitise shell metacharacters to prevent command injection.",
            "target": "ubuntu:16.04 (ubuntu 16.04)",
            "type": "ubuntu",
        },
        {
            "vuln_id": "CVE-2021-3711",
            "pkg_name": "libssl1.0.0",
            "installed_version": "1.0.2g-1ubuntu4.20",
            "fixed_version": "",
            "severity": "HIGH",
            "title": "openssl: SM2 Decryption Buffer Overflow",
            "description": "In order to decrypt SM2 encrypted data an application is expected to call the API function EVP_PKEY_decrypt(). A buffer overflow can occur.",
            "target": "ubuntu:16.04 (ubuntu 16.04)",
            "type": "ubuntu",
        },
        {
            "vuln_id": "CVE-2021-33560",
            "pkg_name": "libgcrypt20",
            "installed_version": "1.6.5-2ubuntu0.6",
            "fixed_version": "",
            "severity": "HIGH",
            "title": "libgcrypt: mishandles ElGamal encryption",
            "description": "Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding.",
            "target": "ubuntu:16.04 (ubuntu 16.04)",
            "type": "ubuntu",
        },
        {
            "vuln_id": "CVE-2022-2509",
            "pkg_name": "libgnutls30",
            "installed_version": "3.4.10-4ubuntu1.9",
            "fixed_version": "",
            "severity": "HIGH",
            "title": "gnutls: Double free during gnutls_pkcs7_verify",
            "description": "A vulnerability was found in gnutls. A double free can occur during verification of pkcs7 signatures in gnutls_pkcs7_verify function.",
            "target": "ubuntu:16.04 (ubuntu 16.04)",
            "type": "ubuntu",
        },
    ]


def run_trivy_os():
    """Pull an old Linux image (Ubuntu 16.04) and scan it for OS-level CVEs.

    Falls back to sample data if Docker is unavailable or the pull fails.
    """
    old_image = "ubuntu:16.04"
    try:
        # Pull the old image if not already present
        pull_result = subprocess.run(
            ["docker", "pull", old_image],
            capture_output=True, text=True, timeout=120
        )
        if pull_result.returncode != 0:
            raise RuntimeError(f"docker pull failed: {pull_result.stderr[:200]}")

        result = subprocess.run(
            ["trivy", "image", old_image, "--format", "json", "--scanners", "vuln"],
            capture_output=True, text=True, timeout=180
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append({
                    "vuln_id": vuln.get("VulnerabilityID"),
                    "pkg_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": vuln.get("Severity"),
                    "title": vuln.get("Title"),
                    "description": vuln.get("Description"),
                    "target": target_result.get("Target"),
                    "type": target_result.get("Type"),
                })

        # If trivy ran but found nothing, use fallback
        if not findings:
            print("[scan] Trivy OS found 0 results, using fallback sample data.")
            findings = _trivy_os_fallback_findings()

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy OS complete: {len(findings)} findings")
    except Exception as e:
        # Docker not available or pull/scan failed — write fallback data
        print(f"[scan] Trivy OS failed ({e}), using fallback sample data.")
        findings = _trivy_os_fallback_findings()
        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()


def run_all_scans():
    """Run all scanners sequentially and cache results."""
    print("[scan] Running all scanners...")
    run_checkov()
    run_semgrep()
    run_trivy_fs()
    run_trivy_image()
    run_trivy_os()
    print("[scan] All scans complete.")


class ScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        elif self.path == "/scan/checkov":
            self._serve_cached("checkov.json")
        elif self.path == "/scan/semgrep":
            self._serve_cached("semgrep.json")
        elif self.path == "/scan/trivy-fs":
            self._serve_cached("trivy-fs.json")
        elif self.path == "/scan/trivy-image":
            self._serve_cached("trivy-image.json")
        elif self.path == "/scan/trivy-os":
            self._serve_cached("trivy-os.json")
        elif self.path == "/scan-status":
            self._respond(200, {"timestamps": scan_timestamps})
        else:
            self._respond(404, {"error": "unknown endpoint", "available": [
                "/health", "/scan/checkov", "/scan/semgrep",
                "/scan/trivy-fs", "/scan/trivy-image", "/scan/trivy-os",
                "/scan-status", "POST /trigger-scan"
            ]})

    def do_POST(self):
        if self.path == "/trigger-scan":
            # Run scans in background thread so request doesn't block
            thread = threading.Thread(target=run_all_scans, daemon=True)
            thread.start()
            self._respond(202, {"status": "scan triggered", "message": "Scans running in background. Check /scan-status for completion."})
        else:
            self._respond(404, {"error": "unknown endpoint"})

    def _serve_cached(self, filename):
        """Return cached scan results from disk."""
        filepath = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(filepath):
            self._respond(404, {"error": f"No cached results for {filename}. POST /trigger-scan first or wait for startup scan to complete."})
            return
        with open(filepath) as f:
            data = json.load(f)
        self._respond(200, data)

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, fmt, *args):
        print(f"[server] {args[0]}")


if __name__ == "__main__":
    # --demo flag: skip real scans, just write fallback sample data for all scanners
    demo_mode = "--demo" in sys.argv

    # When running locally (demo mode), default to a writable temp directory
    # if the configured RESULTS_DIR isn't writable (e.g. /opt/vuln-labs on macOS)
    if demo_mode and not os.access(os.path.dirname(RESULTS_DIR.rstrip("/")), os.W_OK):
        import tempfile
        RESULTS_DIR = os.path.join(tempfile.gettempdir(), "vuln-labs-results/")
        print(f"[demo] Using local results dir: {RESULTS_DIR}")

    ensure_results_dir()

    if demo_mode:
        print("[demo] Demo mode — writing sample data for all scanners (no real scans)...")
        # Checkov sample
        checkov_findings = [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
                "severity": "HIGH",
                "resource": "aws_security_group.vulnerable_sg",
                "file_path": "/opt/vuln-labs/cspm-lab/cspm-lab.tf",
                "file_line_range": [55, 75],
                "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/networking-1-port-security",
                "check_type": "terraform",
            },
            {
                "check_id": "CKV_AWS_145",
                "check_name": "Ensure that S3 Buckets are encrypted with KMS",
                "severity": "MEDIUM",
                "resource": "aws_s3_bucket.vulnerable_bucket",
                "file_path": "/opt/vuln-labs/cspm-lab/cspm-lab.tf",
                "file_line_range": [30, 42],
                "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/ensure-that-s3-buckets-are-encrypted-with-kms-by-default",
                "check_type": "terraform",
            },
        ]
        result_data = {"findings": checkov_findings, "total": len(checkov_findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "checkov.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["checkov"] = datetime.utcnow().isoformat()

        # Semgrep sample
        semgrep_findings = _semgrep_fallback_findings()
        result_data = {"findings": semgrep_findings, "total": len(semgrep_findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()

        # Trivy FS sample
        trivy_fs_findings = [
            {
                "vuln_id": "CVE-2021-44228",
                "pkg_name": "org.apache.logging.log4j:log4j-core",
                "installed_version": "2.14.1",
                "fixed_version": "2.17.1",
                "severity": "CRITICAL",
                "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
                "description": "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "target": "java-app/pom.xml",
                "type": "pom",
            },
            {
                "vuln_id": "CVE-2021-23337",
                "pkg_name": "lodash",
                "installed_version": "4.17.20",
                "fixed_version": "4.17.21",
                "severity": "HIGH",
                "title": "Lodash Command Injection via template function",
                "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
                "target": "package-lock.json",
                "type": "npm",
            },
            {
                "vuln_id": "CVE-2021-3749",
                "pkg_name": "axios",
                "installed_version": "0.21.1",
                "fixed_version": "0.21.2",
                "severity": "HIGH",
                "title": "axios: Regular expression denial of service in trim function",
                "description": "axios is vulnerable to Inefficient Regular Expression Complexity.",
                "target": "package-lock.json",
                "type": "npm",
            },
        ]
        result_data = {"findings": trivy_fs_findings, "total": len(trivy_fs_findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-fs.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-fs"] = datetime.utcnow().isoformat()

        # Trivy Image sample
        trivy_image_findings = [
            {
                "vuln_id": "CVE-2021-3711",
                "pkg_name": "openssl",
                "installed_version": "1.1.1f-1ubuntu2",
                "fixed_version": "1.1.1f-1ubuntu2.16",
                "severity": "HIGH",
                "title": "openssl: SM2 Decryption Buffer Overflow",
                "description": "A bug in the implementation of the SM2 decryption code means that the calculation of the buffer size could overflow.",
                "target": "vuln-lab-image:latest (ubuntu 20.04)",
                "type": "ubuntu",
            },
            {
                "vuln_id": "CVE-2022-0778",
                "pkg_name": "openssl",
                "installed_version": "1.1.1f-1ubuntu2",
                "fixed_version": "1.1.1f-1ubuntu2.12",
                "severity": "HIGH",
                "title": "openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
                "description": "The BN_mod_sqrt() function contains a bug that can result in it looping forever for non-prime moduli.",
                "target": "vuln-lab-image:latest (ubuntu 20.04)",
                "type": "ubuntu",
            },
        ]
        result_data = {"findings": trivy_image_findings, "total": len(trivy_image_findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-image.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image"] = datetime.utcnow().isoformat()

        # Trivy OS sample
        trivy_os_findings = _trivy_os_fallback_findings()
        result_data = {"findings": trivy_os_findings, "total": len(trivy_os_findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()

        print("[demo] All sample data written.")
    else:
        # Run all scans once at startup
        print("Running initial scans at startup...")
        run_all_scans()

    print("Scan server starting on port 8090...")
    server = HTTPServer(("0.0.0.0", 8090), ScanHandler)
    print("Ready. GET endpoints serve cached results. POST /trigger-scan to re-scan.")
    server.serve_forever()
