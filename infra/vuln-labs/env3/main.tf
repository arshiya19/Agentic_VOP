# =============================================================================
# Vuln Labs — env3 (Remediation Playground)
# =============================================================================
# This environment runs the same vulnerable applications as env1 but WITHOUT
# the scan server. Used for applying and validating remediation steps.
# Scanners are installed for ad-hoc validation (re-run after fix).
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
      Environment = "env3-remediation"
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
  default     = "t4g.micro"
}

# -----------------------------------------------------------------------------
# Module Instantiation
# -----------------------------------------------------------------------------

module "lab" {
  source = "../modules/lab-instance"

  role                = "remediation"
  name_prefix         = "vop-vuln-lab-env3"
  aws_region          = var.aws_region
  instance_type       = var.instance_type
  install_scanners    = true  # Installed for ad-hoc validation after fixes
  install_scan_server = false # No scan server — this is the remediation target
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_id" {
  description = "EC2 instance ID"
  value       = module.lab.instance_id
}

output "instance_public_ip" {
  description = "Public IP of the remediation playground instance"
  value       = module.lab.instance_public_ip
}

output "security_group_id" {
  description = "Security group ID"
  value       = module.lab.security_group_id
}

output "ssh_command" {
  description = "SSH command to connect"
  value       = module.lab.ssh_command
}
