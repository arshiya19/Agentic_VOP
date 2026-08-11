#!/bin/bash
# =============================================================================
# OS Scan Target Setup Script
# Role: ${role}
# Lightweight instance for Trivy host OS scanning.
# Installs Trivy only — no application labs.
# =============================================================================
set -e

# =============================================================================
# 1. Install basic tools (Amazon Linux 2 uses yum)
# =============================================================================
yum install -y curl unzip python3

# =============================================================================
# 2. Install Trivy
# =============================================================================
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

%{ if install_scan_server ~}
# =============================================================================
# 3. Deploy scan server (scan-source role only)
# =============================================================================
mkdir -p /opt/vuln-labs/results

cat > /opt/vuln-labs/scan-server.py << 'SRVEOF'
"""Lightweight scan server for OS vulnerability scanning.

Endpoints:
  GET  /health       — liveness check
  GET  /scan/trivy-os — returns cached Trivy rootfs scan results
  GET  /scan-status  — shows when the scan was last run
  POST /trigger-scan — re-runs the scan and updates cache
"""

import json
import os
import subprocess
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

RESULTS_DIR = "/opt/vuln-labs/results/"
scan_timestamps = {}


def run_trivy_os():
    """Scan the host OS rootfs for vulnerabilities."""
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
                    "os": "amazon-linux-2 (host)",
                })

        result_data = {"findings": findings, "total": len(findings),
                       "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy OS complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy OS failed: {e}")
        error_data = {"findings": [], "total": 0, "error": str(e),
                      "scanned_at": datetime.utcnow().isoformat()}
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()


class ScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        elif self.path == "/scan/trivy-os":
            self._serve_cached("trivy-os.json")
        elif self.path == "/scan-status":
            self._respond(200, {"timestamps": scan_timestamps})
        else:
            self._respond(404, {"error": "unknown endpoint", "available": [
                "/health", "/scan/trivy-os", "/scan-status", "POST /trigger-scan"
            ]})

    def do_POST(self):
        if self.path == "/trigger-scan":
            thread = threading.Thread(target=run_trivy_os, daemon=True)
            thread.start()
            self._respond(202, {"status": "scan triggered",
                                "message": "Scan running in background. Check /scan-status for completion."})
        else:
            self._respond(404, {"error": "unknown endpoint"})

    def _serve_cached(self, filename):
        filepath = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(filepath):
            self._respond(404, {"error": f"No cached results. POST /trigger-scan first or wait for startup scan."})
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
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Run initial scan
    print("Running initial Trivy OS scan...")
    run_trivy_os()

    print("Scan server starting on port ${scan_server_port}...")
    server = HTTPServer(("0.0.0.0", ${scan_server_port}), ScanHandler)
    print("Ready. GET /scan/trivy-os for cached results. POST /trigger-scan to re-scan.")
    server.serve_forever()
SRVEOF

# Start scan server as a systemd service
cat > /etc/systemd/system/scan-server.service << 'SVCEOF'
[Unit]
Description=VOP OS Scan Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/vuln-labs/scan-server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable scan-server
systemctl start scan-server
%{ endif ~}

# =============================================================================
# Done — write a marker file
# =============================================================================
mkdir -p /opt/vuln-labs
echo "OS scan target setup complete (role: ${role}) at $(date)" > /opt/vuln-labs/SETUP_COMPLETE
