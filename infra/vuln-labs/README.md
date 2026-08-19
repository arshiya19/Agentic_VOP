# Vulnerable Lab Environments

Two EC2 instances with intentionally vulnerable applications for the VOP pipeline.

## Architecture

```
env1 (Scan Source)                          env2 (Remediation Playground)
┌──────────────────────────────┐            ┌──────────────────────────────┐
│  Vulnerable apps             │            │  Vulnerable apps (same)      │
│  + Scanners installed        │            │  + Scanners (ad-hoc only)    │
│  + Scan server (:8090)       │            │  + SSH access for fixes      │
│                              │            │                              │
│  VOP fetches results here    │            │  VOP applies fixes here      │
└──────────────────────────────┘            └──────────────────────────────┘
         │                                            │
         └──────── Same vulnerable code ──────────────┘
```

## What's on each instance

| Lab | Path | Scanner | Vulnerabilities |
|-----|------|---------|-----------------|
| AppSec (SAST) | `/opt/vuln-labs/appsec-lab/` | Semgrep | SQLi, XSS, SSRF, command injection, hardcoded secrets, etc. |
| AppSec (SCA) | `/opt/vuln-labs/appsec-lab/` | Trivy FS | Vulnerable pinned Python dependencies |
| Infra | `/opt/vuln-labs/infra-lab/` | Trivy Image | Outdated Ubuntu + OpenSSL |
| CSPM | `/opt/vuln-labs/cspm-lab/` | Checkov | Public S3, open SSH SG |

## Directory Structure

```
infra/vuln-labs/
├── modules/
│   └── lab-instance/           # Reusable Terraform module
│       ├── main.tf             # EC2, SG, SSH key
│       ├── variables.tf        # role, scanners, scan-server toggles
│       ├── outputs.tf
│       └── user-data.sh.tpl    # Templated bootstrap script
│
├── env1/                       # Scan Source (Terraform root)
│   ├── main.tf
│   ├── backend.hcl
│   └── terraform.tfvars
│
├── env2/                       # Remediation Playground (Terraform root)
│   ├── main.tf
│   ├── backend.hcl
│   └── terraform.tfvars
│
├── vuln-samples/
│   └── cspm-lab.tf             # Intentionally vulnerable TF (never applied)
│
├── scan-server.py              # Reference copy of the scan server
├── deploy-scan-server.sh       # Deploys CSPM samples + verifies server
├── .gitignore
└── README.md
```

## Management via GitHub Actions

Use the **Vuln Labs** workflow (Actions → Vuln Labs → Run workflow):

| Input | Options |
|-------|---------|
| Environment | `env1-scan-source`, `env2-remediation` |
| Action | `deploy`, `destroy`, `stop`, `start` |

Actions:
- **deploy** — Runs fmt, validate, Checkov (excludes vuln-samples), then `terraform apply`
- **destroy** — Full teardown (`terraform destroy`)
- **stop** — Stops the EC2 instance (preserves EBS, no compute billing)
- **start** — Starts a stopped instance (note: public IP may change)

## Local Usage

```bash
# Deploy env1 (scan source)
cd infra/vuln-labs/env1
terraform init -backend-config=backend.hcl
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars

# Deploy env2 (remediation playground)
cd infra/vuln-labs/env2
terraform init -backend-config=backend.hcl
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars

# Destroy when done
cd infra/vuln-labs/env1 && terraform destroy -var-file=terraform.tfvars
cd infra/vuln-labs/env2 && terraform destroy -var-file=terraform.tfvars
```

### deploy-scan-server.sh (optional)

The scan server and all vulnerable samples (including CSPM) are automatically
provisioned on instance creation via user-data. No manual post-deploy step is
required.

`deploy-scan-server.sh` is a convenience script for:
- **Updating** the CSPM sample on a running instance if you change `vuln-samples/cspm-lab.tf`
- **Verifying** the scan server health after a deploy or restart

```bash
# Only needed if you update cspm-lab.tf after the instance is already running
cd <repo-root>
bash infra/vuln-labs/deploy-scan-server.sh
```

## End-to-End Flow

1. Deploy env1 → instance bootstraps with vulnerable apps, scanners, and scan server
2. VOP fetches from `http://<env1-ip>:8090/scan/*` (server starts automatically)
3. Sub-Agent 1 normalizes → Sub-Agent 2 enriches + generates remediation
4. Deploy env2 → identical vulnerable environment (no scan server)
5. Apply remediation to env2 (auto via SSH agent or manual)
6. Validate: SSH into env2, run the relevant scanner, confirm finding is gone

## Cost

- `t4g.micro` is free-tier eligible (750 hrs/month for first 12 months)
- Use **stop** action when not in use to avoid compute charges
- **destroy** when no longer needed
