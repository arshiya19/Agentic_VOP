# =============================================================================
# CSPM Lab — Intentionally Misconfigured Terraform (Scan Target Only)
# =============================================================================
# This file is NEVER applied as real infrastructure. It is copied to the EC2
# instance at /opt/vuln-labs/cspm-lab/ where Checkov scans it to produce
# CSPM findings for the VOP platform.
#
# Intentional findings (3):
#   1. S3 bucket — no encryption, no versioning, no public access block
#   2. Security group — SSH open to the world (0.0.0.0/0)
#   3. IAM role — overly permissive policy (Action: *, Resource: *)
#
# Everything else in this file follows best practices.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# -----------------------------------------------------------------------------
# FINDING 1: S3 Bucket — intentionally misconfigured
# Missing: encryption, versioning, public access block, logging
# Checkov checks triggered:
#   CKV_AWS_18  — Ensure S3 bucket has access logging
#   CKV_AWS_19  — Ensure S3 bucket has server-side encryption
#   CKV_AWS_21  — Ensure S3 bucket has versioning enabled
#   CKV2_AWS_6  — Ensure S3 bucket has a public access block
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "cspm-lab-intentionally-public-bucket"
  force_destroy = true

  tags = {
    Name    = "cspm-lab-vulnerable-bucket"
    Purpose = "checkov-scan-target"
  }
}

# Intentionally NO aws_s3_bucket_server_side_encryption_configuration
# Intentionally NO aws_s3_bucket_versioning
# Intentionally NO aws_s3_bucket_public_access_block
# Intentionally NO aws_s3_bucket_logging

# -----------------------------------------------------------------------------
# FINDING 2: Security Group — SSH open to the world
# Missing: restricted CIDR block for SSH access
# Checkov checks triggered:
#   CKV_AWS_24  — Ensure no security group allows ingress from 0.0.0.0/0 to port 22
# -----------------------------------------------------------------------------

resource "aws_security_group" "vulnerable_sg" {
  name        = "cspm-lab-open-sg"
  description = "INTENTIONALLY OPEN — Checkov scan target"

  ingress {
    description = "SSH open to world — intentional misconfiguration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "cspm-lab-open-sg"
    Purpose = "checkov-scan-target"
  }
}
