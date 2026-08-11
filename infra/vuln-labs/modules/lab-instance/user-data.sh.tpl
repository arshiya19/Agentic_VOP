#!/bin/bash
# =============================================================================
# Vulnerable Lab Setup Script
# Role: ${role}
# Provisions intentionally vulnerable applications for scanner demos.
# Scanner installation is conditional based on instance role.
# =============================================================================
set -e

export DEBIAN_FRONTEND=noninteractive

# Update system packages (retry up to 3 times on transient mirror failures)
for i in 1 2 3; do
  apt-get update -y && break
  echo "apt-get update failed (attempt $i/3), retrying in 10s..."
  sleep 10
done
for i in 1 2 3; do
  apt-get install -y --fix-missing git curl unzip python3 python3-pip python3-venv nodejs npm docker.io && break
  echo "apt-get install failed (attempt $i/3), retrying in 10s..."
  apt-get update -y
  sleep 10
done

# Enable and start Docker
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

# =============================================================================
# 0. Install Terraform (needed to apply CSPM lab resources)
# =============================================================================
curl -fsSL https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_amd64.zip -o /tmp/terraform.zip
unzip -o /tmp/terraform.zip -d /usr/local/bin/
rm -f /tmp/terraform.zip
terraform version

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

# Build the vulnerable image (timeout after 5 minutes)
cd /opt/vuln-labs/infra-lab
timeout 300 docker build -t vuln-lab-image:latest . || echo "WARNING: infra-lab docker build timed out or failed"

# =============================================================================
# 3b. Java Lab — Old Tomcat + JDK 8 on Debian (for Trivy Image)
#     Produces JDK CVEs, Tomcat CVEs, and OS-level Debian CVEs.
#     These do NOT overlap with the SCA lab (which scans pom.xml manifests).
# =============================================================================
mkdir -p /opt/vuln-labs/java-image-lab
cat > /opt/vuln-labs/java-image-lab/Dockerfile << 'JDKREOF'
# Intentionally outdated Java runtime environment
# Tomcat 9.0.30 + OpenJDK 8 on Debian Buster — has JDK CVEs, Tomcat CVEs,
# and Debian OS-level CVEs baked into the base image layers.
# No apt-get needed — Debian Buster repos are EOL and unavailable.
FROM tomcat:9.0.30-jdk8-openjdk

# Deploy a placeholder webapp
RUN mkdir -p /usr/local/tomcat/webapps/ROOT
RUN echo '<html><body><h1>Vulnerable Java App</h1></body></html>' > /usr/local/tomcat/webapps/ROOT/index.html

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
EXPOSE 8080
CMD ["catalina.sh", "run"]
JDKREOF

cd /opt/vuln-labs/java-image-lab
timeout 300 docker build -t vuln-java-image:latest . || echo "WARNING: java-image-lab docker build timed out or failed"

# =============================================================================
# 3c. Python Lab — Old Python 3.8 with vulnerable pip packages (for Trivy Image)
#     Produces OS CVEs (Debian buster) + installed pip package CVEs.
#     Remediation: update base image or pin newer package versions in Dockerfile.
# =============================================================================
mkdir -p /opt/vuln-labs/python-image-lab
cat > /opt/vuln-labs/python-image-lab/Dockerfile << 'PYDKREOF'
# Intentionally outdated Python runtime with vulnerable dependencies
FROM python:3.8-slim-buster

# Install vulnerable pip packages directly into the image
RUN pip install --no-cache-dir \
    flask==2.0.0 \
    jinja2==3.0.0 \
    requests==2.25.0 \
    cryptography==3.3.2 \
    pyyaml==5.3.1 \
    urllib3==1.26.4 \
    werkzeug==2.0.0 \
    setuptools==58.0.0 \
    pillow==8.1.0 \
    certifi==2020.12.5

# Add a placeholder app
RUN mkdir -p /app
RUN echo 'from flask import Flask; app = Flask(__name__)' > /app/main.py

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
WORKDIR /app
EXPOSE 5000
CMD ["python", "main.py"]
PYDKREOF

cd /opt/vuln-labs/python-image-lab
timeout 300 docker build -t vuln-python-image:latest . || echo "WARNING: python-image-lab docker build timed out or failed"

# =============================================================================
# 4. CSPM Lab — Vulnerable Terraform (applied as real AWS resources)
#    Creates intentionally misconfigured S3 bucket + Security Group.
#    SA4 will later fix these by editing the .tf and re-applying.
# =============================================================================
mkdir -p /opt/vuln-labs/cspm-lab
cat > /opt/vuln-labs/cspm-lab/main.tf << 'TFEOF'
# =============================================================================
# CSPM Lab — Intentionally Misconfigured AWS Resources
# =============================================================================
# These resources are REAL and INTENTIONALLY VULNERABLE.
# Checkov scans this file and reports findings.
# SA4 (automated fixer) will remediate by editing this file and re-applying.
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

  backend "s3" {
    # Configured via: terraform init -backend-config=backend.hcl
  }
}

provider "aws" {
  region = "${aws_region}"
}

data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# FINDING 1: S3 Bucket — intentionally misconfigured
# Missing: encryption, versioning, public access block, logging
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "cspm-lab-${name_prefix}-bucket"
  force_destroy = true

  tags = {
    Name    = "cspm-lab-${name_prefix}-bucket"
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
  name        = "cspm-lab-${name_prefix}-open-sg"
  description = "INTENTIONALLY OPEN - Checkov scan target"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH open to world - intentional misconfiguration"
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
    Name    = "cspm-lab-${name_prefix}-open-sg"
    Purpose = "checkov-scan-target"
  }
}
TFEOF

# Create backend config for CSPM lab Terraform state
cat > /opt/vuln-labs/cspm-lab/backend.hcl << 'BKEOF'
bucket         = "${terraform_state_bucket}"
key            = "vuln-labs/cspm-lab/${name_prefix}/terraform.tfstate"
region         = "${aws_region}"
encrypt        = true
dynamodb_table = "${terraform_lock_table}"
BKEOF

# Initialize and apply the CSPM lab Terraform to create real resources
cd /opt/vuln-labs/cspm-lab
terraform init -backend-config=backend.hcl -input=false
terraform apply -auto-approve -input=false || echo "WARNING: CSPM lab terraform apply failed. Resources may not exist."

%{ if install_scanners ~}
# =============================================================================
# 5. Install Scanners
# =============================================================================

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Semgrep
pip3 install semgrep --break-system-packages 2>/dev/null || pip3 install semgrep

# Install Checkov
# Pin argcomplete<3.6 to avoid Python 3.8 incompatibility with argcomplete 3.7+
pip3 install "argcomplete<3.6" --break-system-packages 2>/dev/null || pip3 install "argcomplete<3.6"
pip3 install checkov --break-system-packages 2>/dev/null || pip3 install checkov
%{ endif ~}

%{ if install_scan_server ~}
# =============================================================================
# 6. Install and Start Scan Server (scan-source role only)
# Download from GitHub to keep user-data under the 16KB limit.
# =============================================================================
curl -fsSL "https://raw.githubusercontent.com/arshiya19/Agentic_VOP/main/infra/vuln-labs/scan-server.py" \
  -o /opt/vuln-labs/scan-server.py

# Replace port placeholder if needed
sed -i 's/8090/${scan_server_port}/g' /opt/vuln-labs/scan-server.py

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
