#!/bin/bash
# =============================================================================
# Deploy Scan Server to env1 (Scan Source)
# =============================================================================
# Copies the CSPM sample file and verifies the scan server is running.
# The scan server itself is installed via user-data on instance creation.
#
# Run from the repo root:
#   bash infra/vuln-labs/deploy-scan-server.sh
#
# Prerequisites:
#   - env1 must be deployed (terraform apply from infra/vuln-labs/env1/)
#   - The SSH key file must exist at infra/vuln-labs/env1/vop-vuln-lab-env1-key.pem
# =============================================================================
set -e

ENV1_DIR="infra/vuln-labs/env1"

# Get the public IP from Terraform state
echo "==> Reading env1 instance IP from Terraform output..."
PUBLIC_IP=$(cd "$ENV1_DIR" && terraform output -raw instance_public_ip)

if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "" ]; then
  echo "ERROR: Could not read instance_public_ip from env1 Terraform state."
  echo "       Make sure env1 is deployed: cd $ENV1_DIR && terraform apply"
  exit 1
fi

KEY="$ENV1_DIR/vop-vuln-lab-env1-key.pem"
HOST="ubuntu@$PUBLIC_IP"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no"
SCP="scp -i $KEY -o StrictHostKeyChecking=no"

echo "==> Target: $HOST"

echo "==> Copying CSPM sample to instance for Checkov scanning..."
$SSH $HOST "mkdir -p /opt/vuln-labs/cspm-lab"
$SCP infra/vuln-labs/vuln-samples/cspm-lab.tf $HOST:/opt/vuln-labs/cspm-lab/

echo "==> Checking scan server status..."
$SSH $HOST "systemctl is-active scan-server && echo 'Scan server is running' || echo 'Scan server is NOT running'"

echo "==> Testing health endpoint..."
sleep 2
curl -sf "http://$PUBLIC_IP:8090/health" && echo "" || echo "WARNING: Health check failed. Instance may still be bootstrapping."

echo ""
echo "============================================="
echo "Scan server: http://$PUBLIC_IP:8090"
echo "============================================="
echo ""
echo "Available endpoints:"
echo "  GET http://$PUBLIC_IP:8090/health          (liveness)"
echo "  GET http://$PUBLIC_IP:8090/scan/checkov    (CSPM)"
echo "  GET http://$PUBLIC_IP:8090/scan/semgrep    (SAST)"
echo "  GET http://$PUBLIC_IP:8090/scan/trivy-fs   (SCA)"
echo "  GET http://$PUBLIC_IP:8090/scan/trivy-image (Infra)"
echo ""
echo "Register in VOP connection_registry with:"
echo "  endpoint: http://$PUBLIC_IP:8090/scan/<scanner>"
echo "  metadata: {\"connector_type\": \"user_endpoint\", \"response_path\": \"findings\"}"
