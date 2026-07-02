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
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

CSPM_PATH = "/opt/vuln-labs/cspm-lab/"
SAST_PATH = "/opt/vuln-labs/sast-lab/"
SCA_PATH = "/opt/vuln-labs/sca-lab/"
INFRA_IMAGE = "vuln-lab-image:latest"
RESULTS_DIR = "/opt/vuln-labs/results/"

# Track when each scan was last run
scan_timestamps = {}
scan_lock = threading.Lock()


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def run_checkov():
    """Run Checkov and cache results."""
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


def run_semgrep():
    """Run Semgrep and cache results."""
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "auto", SAST_PATH, "--json"],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout) if result.stdout else {}
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

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
        print(f"[scan] Semgrep complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Semgrep failed: {e}")


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


def run_trivy_os():
    """Pull an old Linux image (Ubuntu 16.04) and scan it for OS-level CVEs."""
    old_image = "ubuntu:16.04"
    try:
        # Pull the old image if not already present
        subprocess.run(["docker", "pull", old_image], capture_output=True, timeout=120)

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
                    "os": "ubuntu 16.04 (end-of-life)",
                })

        result_data = {"findings": findings, "total": len(findings), "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy OS (ubuntu:16.04) complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy OS failed: {e}")


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
    ensure_results_dir()

    # Run all scans once at startup
    print("Running initial scans at startup...")
    run_all_scans()

    print("Scan server starting on port 8090...")
    server = HTTPServer(("0.0.0.0", 8090), ScanHandler)
    print("Ready. GET endpoints serve cached results. POST /trigger-scan to re-scan.")
    server.serve_forever()
