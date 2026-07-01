variable "env" {
  description = "Deployment environment (dev or prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.env)
    error_message = "Environment must be one of: dev, prod."
  }
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "github_repository" {
  description = "GitHub repository in 'owner/repo' format for OIDC trust policies"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in 'owner/repo' format."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the application server"
  type        = string
  default     = "t4g.small"
}

variable "volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into the EC2 instance (e.g., GitHub Actions runner IPs)"
  type        = list(string)
  default     = []
}
