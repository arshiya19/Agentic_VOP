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
  description = "GitHub repository in 'owner/repo' format for the OIDC trust policy on the CI signing role. Change this one value when the repo migrates to a new owner."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in 'owner/repo' format."
  }
}

variable "vpc_cidr" {
  description = "IPv4 CIDR for the image-forge VPC. Default reuses 10.1.0.0/16 (freed by removing the manual VOP-vpc-adhoc VPC)."
  type        = string
  default     = "10.1.0.0/16"
}

variable "public_subnet_cidr" {
  description = "IPv4 CIDR for the image-forge public subnet (must be within vpc_cidr)."
  type        = string
  default     = "10.1.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type for the build server (ARM64 / Graviton)"
  type        = string
  default     = "t4g.medium"
}

variable "volume_size" {
  description = "Root EBS volume size in GB (image builds need headroom for layers)"
  type        = number
  default     = 40
}

variable "ecr_repository_name" {
  description = "Name of the test ECR repository the build box publishes hardened images to"
  type        = string
  default     = "sisyfix-hardened-base-test"
}

variable "ecr_image_tag_mutability" {
  description = "ECR tag mutability. MUTABLE is required when cosign stores signatures/attestations as derived OCI tags (sha256-<digest>.sig/.att) in the same repo — IMMUTABLE blocks re-signing with TAG_INVALID. Integrity comes from signing the immutable digest + Rekor, not from ECR tag immutability. Production target: immutable image tags with a mutability exclusion for *.sig/*.att."
  type        = string
  default     = "MUTABLE"

  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ecr_image_tag_mutability must be MUTABLE or IMMUTABLE."
  }
}

variable "ecr_untagged_expire_days" {
  description = "Expire untagged images in the test repo after this many days (keeps throwaway build artifacts from piling up)"
  type        = number
  default     = 7
}

variable "sbom_expire_days" {
  description = "Expire SBOM artifacts (and noncurrent versions) in the SBOM bucket after this many days."
  type        = number
  default     = 30
}

# --- Supply-chain toolchain versions (installed by user-data) ---
# Pinned so the build host is reproducible. Bump deliberately.

variable "cosign_version" {
  description = "Sigstore cosign version to install on the build box (signing + attestation). Must match an existing release tag at github.com/sigstore/cosign/releases (without the leading 'v')."
  type        = string
  default     = "2.4.3"
}

variable "syft_version" {
  description = "Anchore syft version installed via the official install.sh (SBOM generation). Must match an existing release tag at github.com/anchore/syft/releases (without the leading 'v')."
  type        = string
  default     = "1.18.1"
}

variable "trivy_version" {
  description = "Aqua trivy version installed via the official contrib/install.sh (vulnerability scan gate). Must match an existing release tag at github.com/aquasecurity/trivy/releases (without the leading 'v')."
  type        = string
  default     = "0.69.3"
}
