# =============================================================================
# Vuln Labs — env1 (Scan Source)
# =============================================================================
# This environment runs the vulnerable applications WITH scanners installed
# and the scan server running. VOP fetches scan results from here.
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
      Environment = "env1-scan-source"
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

  role                   = "scan-source"
  name_prefix            = "vop-vuln-lab-env1"
  aws_region             = var.aws_region
  instance_type          = var.instance_type
  install_scanners       = true
  install_scan_server    = true
  scan_server_port       = 8090
  terraform_state_bucket = "sisyfix-terraform-state-486655355038"
  terraform_lock_table   = "sisyfix-terraform-locks"

  # Old Ubuntu 20.04 LTS snapshot — has 100+ unpatched CVEs (MEDIUM + HIGH)
  # for Trivy OS scanning demos
  ami_override = "ami-0dba2cb6798deb6d8"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_id" {
  description = "EC2 instance ID"
  value       = module.lab.instance_id
}

output "instance_public_ip" {
  description = "Public IP of the scan source instance"
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

output "scan_server_url" {
  description = "Base URL of the scan server"
  value       = "http://${module.lab.instance_public_ip}:8090"
}
