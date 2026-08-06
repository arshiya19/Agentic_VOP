# =============================================================================
# Vuln Labs — env4 (OS Scan Source — Amazon Linux 2)
# =============================================================================
# Lightweight instance for Trivy host OS scanning.
# Runs an older Amazon Linux 2 AMI with known vulnerabilities.
# Scan server exposes /scan/trivy-os for VOP to fetch results.
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
      Environment = "env4-os-scan-source"
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

  role                   = "scan-source"
  name_prefix            = "vop-vuln-lab-env4"
  aws_region             = var.aws_region
  instance_type          = var.instance_type
  install_scan_server    = true
  scan_server_port       = 8090
  terraform_state_bucket = "sisyfix-terraform-state-486655355038"
  terraform_lock_table   = "sisyfix-terraform-locks"

  # Amazon Linux 2 AMI (older, from 2022) — has known OS-level vulnerabilities
  # amzn2-ami-hvm-2.0.20220912.1-x86_64-gp2
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
  description = "Public IP of the OS scan source instance"
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

output "scan_server_url" {
  description = "Base URL of the scan server"
  value       = "http://${module.os_target.instance_public_ip}:8090"
}
