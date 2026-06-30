#!/bin/bash
# =============================================================================
# Vulnerable Lab Setup Script
# Role: ${role}
# Provisions intentionally vulnerable applications for scanner demos.
# Scanner installation is conditional based on instance role.
# =============================================================================
set -e

export DEBIAN_FRONTEND=noninteractive

# Update system packages
apt-get update -y
apt-get install -y git curl unzip python3 python3-pip python3-venv nodejs npm docker.io

# Enable and start Docker
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

# =============================================================================
# 1. SAST Lab — Flask app with SQL injection (for Semgrep)
# =============================================================================
mkdir -p /opt/vuln-labs/sast-lab
cat > /opt/vuln-labs/sast-lab/app.py << 'APPEOF'
"""Intentionally vulnerable Flask app — SQL injection demo for Semgrep."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('/opt/vuln-labs/sast-lab/users.db')
    return conn

@app.route('/setup')
def setup():
    conn = get_db()
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password1', 'user1@example.com')")
    conn.commit()
    conn.close()
    return jsonify({"status": "database initialized"})

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    # VULN: SQL Injection — string concatenation in query
    conn = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"status": "logged in", "user": user[1]})
    return jsonify({"status": "invalid credentials"}), 401

@app.route('/search')
def search():
    term = request.args.get('q', '')
    # VULN: SQL Injection — unsanitized user input in query
    conn = get_db()
    query = "SELECT * FROM users WHERE username LIKE '%" + term + "%'"
    cursor = conn.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify({"results": results})

@app.route('/user/<user_id>')
def get_user(user_id):
    conn = get_db()
    # VULN: SQL Injection — direct interpolation of path parameter
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"user": {"id": user[0], "username": user[1], "email": user[3]}})
    return jsonify({"error": "not found"}), 404

@app.route('/debug')
def debug():
    # VULN: Sensitive data exposure — debug endpoint in production
    import os
    return jsonify({
        "env": dict(os.environ),
        "db_path": "/opt/vuln-labs/sast-lab/users.db"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
APPEOF

cat > /opt/vuln-labs/sast-lab/requirements.txt << 'REQEOF'
flask==2.3.0
REQEOF

cd /opt/vuln-labs/sast-lab
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# =============================================================================
# 2. SCA Lab — Node project with vulnerable dependencies (for Trivy FS)
# =============================================================================
mkdir -p /opt/vuln-labs/sca-lab
cat > /opt/vuln-labs/sca-lab/package.json << 'PKGEOF'
{
  "name": "vuln-sca-lab",
  "version": "1.0.0",
  "description": "Intentionally vulnerable dependencies for Trivy FS scanning",
  "dependencies": {
    "lodash": "4.17.20",
    "express": "4.17.1",
    "axios": "0.21.1",
    "minimist": "1.2.5",
    "node-fetch": "2.6.1",
    "tar": "4.4.13",
    "glob-parent": "5.1.1",
    "path-parse": "1.0.6",
    "ws": "7.4.5",
    "json5": "1.0.1"
  }
}
PKGEOF

# Java/Maven project with Log4j vulnerability
mkdir -p /opt/vuln-labs/sca-lab/java-app
cat > /opt/vuln-labs/sca-lab/java-app/pom.xml << 'POMEOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.vuln.lab</groupId>
    <artifactId>vuln-java-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <!-- VULN: Log4j 2.14.1 — CVE-2021-44228 (Log4Shell) -->
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
        <!-- VULN: Spring Framework — CVE-2022-22965 (Spring4Shell) -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>5.3.17</version>
        </dependency>
        <!-- VULN: Jackson Databind — CVE-2020-36518 -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.13.2</version>
        </dependency>
    </dependencies>
</project>
POMEOF

cd /opt/vuln-labs/sca-lab
npm install --ignore-scripts 2>/dev/null || true

# =============================================================================
# 3. Infra Lab — Dockerfile with outdated base image (for Trivy Image)
# =============================================================================
mkdir -p /opt/vuln-labs/infra-lab
cat > /opt/vuln-labs/infra-lab/Dockerfile << 'DKREOF'
# Intentionally outdated base image with known CVEs
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    openssl=1.1.1f-1ubuntu2 \
    curl \
    wget \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
# VULN: Using ADD instead of COPY for local files
ADD app.py /app/app.py

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
DKREOF

cat > /opt/vuln-labs/infra-lab/app.py << 'PYEOF'
print("placeholder app")
PYEOF

# Build the vulnerable image
cd /opt/vuln-labs/infra-lab
docker build -t vuln-lab-image:latest . 2>/dev/null || true

# =============================================================================
# 4. CSPM Lab — Vulnerable Terraform samples (for Checkov)
#    These files are scan targets only — never applied as real infrastructure.
# =============================================================================
mkdir -p /opt/vuln-labs/cspm-lab
cat > /opt/vuln-labs/cspm-lab/cspm-lab.tf << 'TFEOF'
# =============================================================================
# CSPM Lab — Intentionally Misconfigured Terraform (Scan Target Only)
# =============================================================================
# This file is NEVER applied. It exists solely as a Checkov scan target
# to produce CSPM findings for the VOP platform.
#
# Intentional findings:
#   1. S3 bucket — no encryption, no versioning, no public access block
#   2. Security group — SSH open to the world (0.0.0.0/0)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# -----------------------------------------------------------------------------
# FINDING 1: S3 Bucket — intentionally misconfigured
# Missing: encryption, versioning, public access block, logging
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "cspm-lab-intentionally-public-bucket"
  force_destroy = true

  tags = {
    Name    = "cspm-lab-vulnerable-bucket"
    Purpose = "checkov-scan-target"
  }
}

# Intentionally NO aws_s3_bucket_server_side_encryption_configuration
# Intentionally NO aws_s3_bucket_versioning
# Intentionally NO aws_s3_bucket_public_access_block
# Intentionally NO aws_s3_bucket_logging

# -----------------------------------------------------------------------------
# FINDING 2: Security Group — SSH open to the world
# Missing: restricted CIDR block for SSH access
# -----------------------------------------------------------------------------

resource "aws_security_group" "vulnerable_sg" {
  name        = "cspm-lab-open-sg"
  description = "INTENTIONALLY OPEN — Checkov scan target"

  ingress {
    description = "SSH open to world — intentional misconfiguration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "cspm-lab-open-sg"
    Purpose = "checkov-scan-target"
  }
}
TFEOF

%{ if install_scanners ~}
# =============================================================================
# 5. Install Scanners (scan-source role only)
# =============================================================================

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Semgrep
pip3 install semgrep --break-system-packages 2>/dev/null || pip3 install semgrep

# Install Checkov
pip3 install checkov --break-system-packages 2>/dev/null || pip3 install checkov
%{ endif ~}

%{ if install_scan_server ~}
# =============================================================================
# 6. Install and Start Scan Server (scan-source role only)
# =============================================================================
cat > /opt/vuln-labs/scan-server.py << 'SRVEOF'
"""HTTP server that runs scanners on-demand and serves results.

Runs on the EC2 lab instance on port ${scan_server_port}. VOP's user_endpoint
connector hits these endpoints to pull scan results automatically.

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
            self._respond(200, {"findings": findings, "total": len(findings)})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _run_semgrep(self):
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
    print("Scan server starting on port ${scan_server_port}...")
    server = HTTPServer(("0.0.0.0", ${scan_server_port}), ScanHandler)
    print("Ready. Endpoints: /health, /scan/checkov, /scan/semgrep, /scan/trivy-fs, /scan/trivy-image")
    server.serve_forever()
SRVEOF

# Start the scan server as a systemd service for reliability
cat > /etc/systemd/system/scan-server.service << 'SVCEOF'
[Unit]
Description=VOP Vulnerability Lab Scan Server
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
echo "Lab setup complete (role: ${role}) at $(date)" > /opt/vuln-labs/SETUP_COMPLETE
chown -R ubuntu:ubuntu /opt/vuln-labs
