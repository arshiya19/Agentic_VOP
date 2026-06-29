# Vulnerable Lab Environment

Single EC2 instance with intentionally vulnerable applications for scanner demonstrations.

## What's on the instance

| Lab | Path | Scanner | Vulnerabilities |
|-----|------|---------|-----------------|
| SAST | `/opt/vuln-labs/sast-lab/` | Semgrep | Flask app with SQL injection |
| SCA (Node) | `/opt/vuln-labs/sca-lab/` | Trivy FS | lodash, express, Log4j, etc. |
| SCA (Java) | `/opt/vuln-labs/sca-lab/java-app/` | Trivy FS | Log4Shell, Spring4Shell |
| Infra | `/opt/vuln-labs/infra-lab/` | Trivy Image | Outdated Ubuntu + OpenSSL |
| CSPM | This Terraform code itself | Checkov | Public S3, open SSH SG |

## Usage

```bash
cd infra/vuln-labs

# Create the lab
terraform init
terraform plan
terraform apply

# SSH into the instance
ssh -i lab-key.pem ubuntu@<public-ip>

# Run scanners on the instance
semgrep scan --config auto /opt/vuln-labs/sast-lab/ --sarif -o sast-results.sarif
trivy fs /opt/vuln-labs/sca-lab/ --format json -o sca-results.json
trivy image vuln-lab-image:latest --format json -o infra-results.json

# Run Checkov locally against this Terraform (CSPM)
checkov -d . --output-file cspm-results.sarif --output sarif

# Destroy when done (stops billing)
terraform destroy
```

## Cost

- `t3.micro` is free-tier eligible (750 hrs/month for first 12 months)
- S3 bucket is empty, negligible cost
- **Remember to `terraform destroy` when done**
