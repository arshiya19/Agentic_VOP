# =============================================================================
# Vuln Labs — env5 (OS Remediation — Amazon Linux 2)
# =============================================================================
# Replica of env4 for remediation testing.
# Same OS, Trivy installed for ad-hoc validation, no scan server.
# SA4 applies fixes here (yum update, etc.) and re-scans to confirm.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    # Configured via: terraform init -backend-config=backend.hcl
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "sisyfix"
      Component   = "vuln-labs"
      Environment = "env5-os-remediation"
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

# -----------------------------------------------------------------------------
# Module Instantiation
# -----------------------------------------------------------------------------

module "os_target" {
  source = "../modules/os-scan-target"

  role                   = "remediation"
  name_prefix            = "vop-vuln-lab-env5"
  aws_region             = var.aws_region
  instance_type          = var.instance_type
  install_scan_server    = false # No scan server — ad-hoc only
  terraform_state_bucket = "sisyfix-terraform-state-486655355038"
  terraform_lock_table   = "sisyfix-terraform-locks"

  # Same AMI as env4 — identical OS for remediation testing
  ami_id = "ami-0b5eea76982371e91"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_id" {
  description = "EC2 instance ID"
  value       = module.os_target.instance_id
}

output "instance_public_ip" {
  description = "Public IP of the OS remediation instance"
  value       = module.os_target.instance_public_ip
}

output "security_group_id" {
  description = "Security group ID"
  value       = module.os_target.security_group_id
}

output "ssh_command" {
  description = "SSH command to connect"
  value       = module.os_target.ssh_command
}
