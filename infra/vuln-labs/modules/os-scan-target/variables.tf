# =============================================================================
# OS Scan Target Module — Variables
# =============================================================================

variable "role" {
  description = "Role of this instance: scan-source or remediation"
  type        = string

  validation {
    condition     = contains(["scan-source", "remediation"], var.role)
    error_message = "Role must be one of: scan-source, remediation."
  }
}

variable "name_prefix" {
  description = "Name prefix for all resources (e.g., vop-vuln-lab-env4)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for the target OS. Use an older AMI for known vulnerabilities."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
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
  description = "S3 bucket name for Terraform state"
  type        = string
}

variable "terraform_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
}
