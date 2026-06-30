"""HTTP server that runs scanners on-demand and serves results.

Runs on the EC2 lab instance on port 8090. VOP's user_endpoint connector
hits these endpoints to pull scan results automatically.

Endpoints:
  GET /health         — liveness check
  GET /scan/checkov   — runs Checkov on Terraform files, returns JSON findings
  GET /scan/semgrep   — runs Semgrep on Flask app, returns JSON findings
  GET /scan/trivy-fs  — runs Trivy FS on SCA lab, returns JSON findings
  GET /scan/trivy-image — runs Trivy image scan, returns JSON findings
"""

import json
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

CSPM_PATH = "/opt/vuln-labs/cspm-lab/"
SAST_PATH = "/opt/vuln-labs/sast-lab/"
SCA_PATH = "/opt/vuln-labs/sca-lab/"
INFRA_IMAGE = "vuln-lab-image:latest"


class ScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        elif self.path == "/scan/checkov":
            self._run_checkov()
        elif self.path == "/scan/semgrep":
            self._run_semgrep()
        elif self.path == "/scan/trivy-fs":
            self._run_trivy_fs()
        elif self.path == "/scan/trivy-image":
            self._run_trivy_image()
        else:
            self._respond(404, {"error": "unknown endpoint", "available": [
                "/health", "/scan/checkov", "/scan/semgrep",
                "/scan/trivy-fs", "/scan/trivy-image"
            ]})

    def _run_checkov(self):
        """Run Checkov against Terraform files and return findings."""
        try:
            result = subprocess.run(
                ["checkov", "-d", CSPM_PATH, "--output", "json", "--quiet", "--compact"],
                capture_output=True, text=True, timeout=120
            )
            # Checkov returns exit code 1 when it finds issues (expected)
            output = result.stdout or result.stderr
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                # Sometimes checkov wraps in a list
                data = {"raw_output": output[:5000]}

            # Extract failed checks as findings
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

            self._respond(200, {"findings": findings, "total": len(findings)})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _run_semgrep(self):
        """Run Semgrep and return findings."""
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
            self._respond(200, {"findings": findings, "total": len(findings)})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _run_trivy_fs(self):
        """Run Trivy filesystem scan and return findings."""
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
            self._respond(200, {"findings": findings, "total": len(findings)})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _run_trivy_image(self):
        """Run Trivy image scan and return findings."""
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
            self._respond(200, {"findings": findings, "total": len(findings)})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, fmt, *args):
        print(f"[scan-server] {args[0]}")


if __name__ == "__main__":
    print("Scan server starting on port 8090...")
    server = HTTPServer(("0.0.0.0", 8090), ScanHandler)
    print("Ready. Endpoints: /health, /scan/checkov, /scan/semgrep, /scan/trivy-fs, /scan/trivy-image")
    server.serve_forever()
