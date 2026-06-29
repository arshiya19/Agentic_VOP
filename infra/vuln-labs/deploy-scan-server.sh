#!/bin/bash
# Deploys the scan server to the EC2 lab instance and starts it.
# Run from the repo root: bash infra/vuln-labs/deploy-scan-server.sh

set -e

KEY="infra/vuln-labs/lab-key.pem"
HOST="ubuntu@98.83.143.120"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no"
SCP="scp -i $KEY -o StrictHostKeyChecking=no"

echo "==> Copying Terraform files for CSPM scanning..."
$SSH $HOST "mkdir -p /opt/vuln-labs/cspm-lab"
$SCP infra/vuln-labs/main.tf $HOST:/opt/vuln-labs/cspm-lab/

echo "==> Copying scan server..."
$SCP infra/vuln-labs/scan-server.py $HOST:/opt/vuln-labs/scan-server.py

echo "==> Opening port 8090 in security group..."
SG_ID=$(cd infra/vuln-labs && terraform output -raw security_group_id)
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 8090 \
  --cidr 0.0.0.0/0 \
  --region us-east-1 2>/dev/null || echo "  (port 8090 rule already exists)"

echo "==> Starting scan server on EC2 (background)..."
$SSH $HOST "pkill -f scan-server.py 2>/dev/null || true"
$SSH $HOST "nohup python3 /opt/vuln-labs/scan-server.py > /tmp/scan-server.log 2>&1 &"

echo "==> Waiting for server to start..."
sleep 3

echo "==> Testing health endpoint..."
curl -s "http://98.83.143.120:8090/health"
echo ""

echo ""
echo "Done! Scan server is running at http://98.83.143.120:8090"
echo ""
echo "Available endpoints:"
echo "  GET http://98.83.143.120:8090/scan/checkov     (CSPM)"
echo "  GET http://98.83.143.120:8090/scan/semgrep     (SAST)"
echo "  GET http://98.83.143.120:8090/scan/trivy-fs    (SCA)"
echo "  GET http://98.83.143.120:8090/scan/trivy-image (Infra)"
echo ""
echo "Register in VOP connection_registry with:"
echo "  endpoint: http://98.83.143.120:8090/scan/checkov"
echo "  metadata: {\"connector_type\": \"user_endpoint\", \"response_path\": \"findings\"}"
