#!/bin/bash
# =============================================================================
# Vulnerable Lab Setup Script
# Provisions intentionally vulnerable applications for scanner demos.
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
cat > /opt/vuln-labs/sast-lab/app.py << 'EOF'
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
EOF

cat > /opt/vuln-labs/sast-lab/requirements.txt << 'EOF'
flask==2.3.0
EOF

cd /opt/vuln-labs/sast-lab
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# =============================================================================
# 2. SCA Lab — Node project with vulnerable dependencies (for Trivy FS)
# =============================================================================
mkdir -p /opt/vuln-labs/sca-lab
cat > /opt/vuln-labs/sca-lab/package.json << 'EOF'
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
EOF

# Java/Maven project with Log4j vulnerability
mkdir -p /opt/vuln-labs/sca-lab/java-app
cat > /opt/vuln-labs/sca-lab/java-app/pom.xml << 'EOF'
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
EOF

cd /opt/vuln-labs/sca-lab
npm install --ignore-scripts 2>/dev/null || true

# =============================================================================
# 3. Infra Lab — Dockerfile with outdated base image (for Trivy Image)
# =============================================================================
mkdir -p /opt/vuln-labs/infra-lab
cat > /opt/vuln-labs/infra-lab/Dockerfile << 'EOF'
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
EOF

cat > /opt/vuln-labs/infra-lab/app.py << 'EOF'
print("placeholder app")
EOF

# Build the vulnerable image
cd /opt/vuln-labs/infra-lab
docker build -t vuln-lab-image:latest . 2>/dev/null || true

# =============================================================================
# 4. Install scanners on the instance
# =============================================================================

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Semgrep
pip3 install semgrep --break-system-packages 2>/dev/null || pip3 install semgrep

# Install Checkov
pip3 install checkov --break-system-packages 2>/dev/null || pip3 install checkov

# =============================================================================
# Done — write a marker file
# =============================================================================
echo "Lab setup complete at $(date)" > /opt/vuln-labs/SETUP_COMPLETE
chown -R ubuntu:ubuntu /opt/vuln-labs
