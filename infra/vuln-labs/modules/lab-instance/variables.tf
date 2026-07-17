# =============================================================================
# Lab Instance Module — Variables
# =============================================================================

variable "role" {
  description = "Role of this lab instance: scan-source or remediation"
  type        = string

  validation {
    condition     = contains(["scan-source", "remediation"], var.role)
    error_message = "Role must be one of: scan-source, remediation."
  }
}

variable "name_prefix" {
  description = "Name prefix for all resources (e.g., vop-vuln-lab-env1)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for the lab"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t4g.micro"
}

variable "install_scanners" {
  description = "Whether to install scanners (Trivy, Semgrep, Checkov) on this instance"
  type        = bool
  default     = false
}

variable "install_scan_server" {
  description = "Whether to install and start the scan server on this instance"
  type        = bool
  default     = false
}

variable "scan_server_port" {
  description = "Port for the scan server HTTP API"
  type        = number
  default     = 8090
}

variable "vpc_id" {
  description = "VPC ID to place the instance in. If empty, uses the default VPC."
  type        = string
  default     = ""
}

variable "terraform_state_bucket" {
  description = "S3 bucket name for Terraform state (used by CSPM lab on the instance)"
  type        = string
}

variable "terraform_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
}

variable "ami_override" {
  description = "Optional AMI ID to use instead of latest Ubuntu. Set to an older AMI to get OS-level vulnerabilities for Trivy scanning."
  type        = string
  default     = ""
}
