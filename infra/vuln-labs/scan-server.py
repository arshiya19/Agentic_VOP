"""HTTP server that serves pre-computed scan results.

Architecture:
  - Scans run ONCE at startup (or on POST /trigger-scan)
  - Results are cached to /opt/vuln-labs/results/
  - GET /scan/* endpoints return cached results instantly
  - VOP fetches pre-computed results, never triggers a scan

Endpoints:
  GET  /health                  — liveness check
  GET  /scan/checkov            — returns cached Checkov CSPM results
  GET  /scan/semgrep            — returns cached Semgrep SAST results
  GET  /scan/trivy-fs           — returns cached Trivy FS SCA results
  GET  /scan/trivy-image/infra  — returns cached Trivy image results (Ubuntu/OpenSSL)
  GET  /scan/trivy-image/java   — returns cached Trivy image results (Tomcat/JDK)
  GET  /scan/trivy-image/python — returns cached Trivy image results (Python/pip)
  GET  /scan/trivy-os           — returns cached Trivy OS results (host rootfs)
  POST /trigger-scan            — re-runs all scanners and updates cache
  GET  /scan-status             — shows when each scan was last run
"""

import json
import os
import subprocess
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

CSPM_PATH = os.environ.get("VULN_LABS_CSPM_PATH", "/opt/vuln-labs/cspm-lab/")
SAST_PATH = os.environ.get("VULN_LABS_SAST_PATH", "/opt/vuln-labs/sast-lab/")
SCA_PATH = os.environ.get("VULN_LABS_SCA_PATH", "/opt/vuln-labs/sca-lab/")
INFRA_IMAGE = os.environ.get("VULN_LABS_INFRA_IMAGE", "vuln-lab-image:latest")
JAVA_IMAGE = os.environ.get("VULN_LABS_JAVA_IMAGE", "vuln-java-image:latest")
PYTHON_IMAGE = os.environ.get("VULN_LABS_PYTHON_IMAGE", "vuln-python-image:latest")
RESULTS_DIR = os.environ.get("VULN_LABS_RESULTS_DIR", "/opt/vuln-labs/results/")

# Track when each scan was last run
scan_timestamps = {}
scan_lock = threading.Lock()


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def run_checkov():
    """Run Checkov and cache only the 3 key findings (1 per resource type)."""
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
                findings.append({
                    "check_id": f.get("check_id"),
                    "check_name": f.get("check_name") or f.get("check_id"),
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


def run_semgrep():
    """Run Semgrep against the SAST lab and cache results."""
    if not os.path.isdir(SAST_PATH):
        print(f"[scan] Semgrep SKIPPED — SAST lab path does not exist: {SAST_PATH}")
        error_data = {"findings": [], "total": 0, "error": f"SAST path missing: {SAST_PATH}",
                      "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
        return

    # Log what files exist in the SAST path for debugging
    try:
        sast_files = os.listdir(SAST_PATH)
        print(f"[scan] SAST lab contents: {sast_files}")
    except Exception as e:
        print(f"[scan] Cannot list SAST path: {e}")

    try:
        # Write a local rules file to avoid dependency on Semgrep registry
        rules_file = os.path.join(RESULTS_DIR, "semgrep-rules.yaml")
        with open(rules_file, "w") as rf:
            rf.write("""rules:
  - id: sql-injection-format-string
    patterns:
      - pattern-either:
          - pattern: |
              $QUERY = f"...{$VAR}..."
              ...
              $CURSOR = $CONN.execute($QUERY)
          - pattern: |
              $QUERY = "..." + $VAR + "..."
              ...
              $CURSOR = $CONN.execute($QUERY)
          - pattern: $CONN.execute(f"...{$VAR}...")
          - pattern: $CONN.execute("..." + $VAR + "...")
    message: >
      SQL injection via string formatting. Use parameterized queries instead.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH
  - id: flask-debug-enabled
    pattern: $APP.run(..., debug=True, ...)
    message: Flask debug mode enabled in production.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-489"]
      owasp: ["A05:2021 - Security Misconfiguration"]
""")

        # Use local rules + memory limits for small EC2 instances
        result = subprocess.run(
            ["semgrep", "scan",
             "--config", rules_file,
             SAST_PATH, "--json", "--no-git-ignore",
             "--timeout", "60",
             "--max-memory", "256",
             "-j", "1",
             "--optimizations", "none"],
            capture_output=True, text=True, timeout=180
        )
        if result.stderr:
            print(f"[scan] Semgrep stderr: {result.stderr[:500]}")

        if not result.stdout:
            error_data = {"findings": [], "total": 0,
                          "error": f"No stdout. returncode={result.returncode}. stderr={result.stderr[:500]}",
                          "scanned_at": datetime.utcnow().isoformat()}
            with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
                json.dump(error_data, f)
            scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
            print(f"[scan] Semgrep produced no output. stderr: {result.stderr[:200]}")
            return

        data = json.loads(result.stdout)
        results = data.get("results", [])
        errors = data.get("errors", [])
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

        result_data = {"findings": findings, "total": len(findings),
                       "scanned_at": datetime.utcnow().isoformat()}
        # Include errors from semgrep if any (e.g. invalid path, rule download failure)
        if errors:
            result_data["errors"] = errors[:5]
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
        print(f"[scan] Semgrep complete: {len(findings)} findings, {len(errors)} errors")
    except Exception as e:
        print(f"[scan] Semgrep failed: {e}")
        error_data = {"findings": [], "total": 0, "error": str(e),
                      "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(error_data, f)
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


def run_trivy_image_java():
    """Run Trivy image scan on the Java/Tomcat image and cache results."""
    try:
        result = subprocess.run(
            ["trivy", "image", JAVA_IMAGE, "--format", "json", "--scanners", "vuln"],
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
        with open(os.path.join(RESULTS_DIR, "trivy-image-java.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image-java"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image Java complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image Java failed: {e}")


def run_trivy_image_python():
    """Run Trivy image scan on the Python image and cache results.

    Only includes python-pkg (pip) findings — OS-level Debian packages from the
    base image are excluded because they're unfixable (Debian Buster is EOL,
    repos are dead, apt-get update fails). The pip packages are explicitly pinned
    in the Dockerfile and fixable by removing the version pin + rebuild.
    """
    try:
        result = subprocess.run(
            ["trivy", "image", PYTHON_IMAGE, "--format", "json", "--scanners", "vuln"],
            capture_output=True, text=True, timeout=180
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            # Only include python-pkg (pip) findings — skip OS-level debian packages
            result_type = (target_result.get("Type") or "").lower()
            if result_type in ("debian", "ubuntu", "alpine", "redhat", "oracle", "amazon"):
                continue
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
        with open(os.path.join(RESULTS_DIR, "trivy-image-python.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image-python"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image Python complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image Python failed: {e}")


def run_trivy_os():
    """Scan the host OS (Ubuntu 20.04) for OS-level CVEs using trivy rootfs."""
    try:
        result = subprocess.run(
            ["trivy", "rootfs", "/", "--format", "json", "--scanners", "vuln"],
            capture_output=True, text=True, timeout=300
        )

        if not result.stdout:
            error_msg = f"trivy produced no output (rc={result.returncode}): {result.stderr[:300]}"
            print(f"[scan] {error_msg}")
            error_data = {"findings": [], "total": 0, "error": error_msg,
                          "scanned_at": datetime.utcnow().isoformat()}
            with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
                json.dump(error_data, f)
            scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
            return

        data = json.loads(result.stdout)
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
                    "os": "ubuntu 20.04 (host)",
                })

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy OS (host rootfs) complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy OS failed: {e}")
        error_data = {"findings": [], "total": 0, "error": str(e),
                      "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()


def run_all_scans():
    """Run all scanners sequentially and cache results."""
    print("[scan] Running all scanners...")
    run_checkov()
    run_semgrep()
    run_trivy_fs()
    run_trivy_image()
    run_trivy_image_java()
    run_trivy_image_python()
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
        elif self.path == "/scan/trivy-image/infra":
            self._serve_cached("trivy-image.json")
        elif self.path == "/scan/trivy-image/java":
            self._serve_cached("trivy-image-java.json")
        elif self.path == "/scan/trivy-image/python":
            self._serve_cached("trivy-image-python.json")
        elif self.path == "/scan/trivy-image":
            # Backward compatible — serves infra image results
            self._serve_cached("trivy-image.json")
        elif self.path == "/scan/trivy-os":
            self._serve_cached("trivy-os.json")
        elif self.path == "/scan-status":
            self._respond(200, {"timestamps": scan_timestamps})
        else:
            self._respond(404, {"error": "unknown endpoint", "available": [
                "/health", "/scan/checkov", "/scan/semgrep",
                "/scan/trivy-fs", "/scan/trivy-image/infra",
                "/scan/trivy-image/java", "/scan/trivy-image/python",
                "/scan/trivy-os", "/scan-status", "POST /trigger-scan"
            ]})

    def do_POST(self):
        if self.path == "/trigger-scan":
            thread = threading.Thread(target=run_all_scans, daemon=True)
            thread.start()
            self._respond(202, {"status": "scan triggered", "message": "Scans running in background. Check /scan-status for completion."})
        elif self.path == "/trigger-scan/semgrep":
            thread = threading.Thread(target=run_semgrep, daemon=True)
            thread.start()
            self._respond(202, {"status": "semgrep scan triggered"})
        elif self.path == "/trigger-scan/trivy-os":
            thread = threading.Thread(target=run_trivy_os, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-os scan triggered"})
        elif self.path == "/trigger-scan/checkov":
            thread = threading.Thread(target=run_checkov, daemon=True)
            thread.start()
            self._respond(202, {"status": "checkov scan triggered"})
        elif self.path == "/trigger-scan/trivy-fs":
            thread = threading.Thread(target=run_trivy_fs, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-fs scan triggered"})
        elif self.path == "/trigger-scan/trivy-image":
            thread = threading.Thread(target=run_trivy_image, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image (infra) scan triggered"})
        elif self.path == "/trigger-scan/trivy-image-java":
            thread = threading.Thread(target=run_trivy_image_java, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image-java scan triggered"})
        elif self.path == "/trigger-scan/trivy-image-python":
            thread = threading.Thread(target=run_trivy_image_python, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image-python scan triggered"})
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
    ensure_results_dir()

    # Wait for lab setup to complete before scanning.
    # The user-data script writes this marker file as its very last step.
    SETUP_MARKER = "/opt/vuln-labs/SETUP_COMPLETE"
    MAX_WAIT = 300  # 5 minutes max
    waited = 0
    while not os.path.exists(SETUP_MARKER) and waited < MAX_WAIT:
        print(f"[startup] Waiting for lab setup to complete ({waited}s)...")
        time.sleep(10)
        waited += 10

    if not os.path.exists(SETUP_MARKER):
        print(f"[startup] WARNING: {SETUP_MARKER} not found after {MAX_WAIT}s. Running scans anyway.")
    else:
        print(f"[startup] Lab setup complete. Starting scans.")

    # Run all scans once at startup
    print("Running initial scans at startup...")
    run_all_scans()

    print("Scan server starting on port 8090...")
    server = HTTPServer(("0.0.0.0", 8090), ScanHandler)
    print("Ready. GET endpoints serve cached results. POST /trigger-scan to re-scan.")
    server.serve_forever()
