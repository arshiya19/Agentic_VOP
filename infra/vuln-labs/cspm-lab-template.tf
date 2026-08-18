# =============================================================================
# CSPM Lab — Intentionally Misconfigured AWS Resources
# =============================================================================
# These resources are REAL and INTENTIONALLY VULNERABLE.
# Checkov scans this file and reports findings.
# SA4 (automated fixer) will remediate by editing this file and re-applying.
#
# Intentional findings:
#   1. S3 bucket — no encryption, no versioning, no public access block
#   2. Security group — SSH open to the world (0.0.0.0/0)
#   3. KMS key — no rotation enabled
#   4. IAM policy — overly permissive (Action: *, Resource: *)
#   5. CloudWatch Log Group — no encryption, no retention
#   6. SNS Topic — no encryption
#   7. SQS Queue — no encryption
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Configured via: terraform init -backend-config=backend.hcl
  }
}

provider "aws" {
  region = "REGION_PLACEHOLDER"
}

data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# FINDING 1: S3 Bucket — intentionally misconfigured
# Missing: encryption, versioning, public access block, logging
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "cspm-lab-NAME_PLACEHOLDER-bucket"
  force_destroy = true

  tags = {
    Name    = "cspm-lab-NAME_PLACEHOLDER-bucket"
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
# -----------------------------------------------------------------------------

resource "aws_security_group" "vulnerable_sg" {
  name        = "cspm-lab-NAME_PLACEHOLDER-open-sg"
  description = "INTENTIONALLY OPEN - Checkov scan target"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH open to world - intentional misconfiguration"
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
    Name    = "cspm-lab-NAME_PLACEHOLDER-open-sg"
    Purpose = "checkov-scan-target"
  }
}

# -----------------------------------------------------------------------------
# FINDING 3: KMS Key — no rotation enabled
# Checkov: CKV_AWS_7 — Ensure rotation for customer created CMKs is enabled
# -----------------------------------------------------------------------------

resource "aws_kms_key" "vulnerable_key" {
  description             = "CSPM lab KMS key - no rotation"
  deletion_window_in_days = 7
  enable_key_rotation     = false

  tags = {
    Name    = "cspm-lab-NAME_PLACEHOLDER-key"
    Purpose = "checkov-scan-target"
  }
}

resource "aws_kms_alias" "vulnerable_key" {
  name          = "alias/cspm-lab-NAME_PLACEHOLDER-key"
  target_key_id = aws_kms_key.vulnerable_key.key_id
}

# -----------------------------------------------------------------------------
# FINDING 4: IAM Policy — overly permissive (Action: *, Resource: *)
# Checkov: CKV_AWS_63 — Ensure no IAM policies allow * in Action and Resource
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "vulnerable_policy" {
  name        = "cspm-lab-NAME_PLACEHOLDER-overly-permissive"
  description = "INTENTIONALLY OVERLY PERMISSIVE - Checkov scan target"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "cspm-lab-NAME_PLACEHOLDER-overly-permissive"
    Purpose = "checkov-scan-target"
  }
}

# -----------------------------------------------------------------------------
# FINDING 5: CloudWatch Log Group — no encryption, no retention
# Checkov: CKV_AWS_158 — Ensure CloudWatch Log Group is encrypted by KMS
# Checkov: CKV_AWS_338 — Ensure CloudWatch log groups retains logs for at least 1 year
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "vulnerable_log_group" {
  name = "/cspm-lab/NAME_PLACEHOLDER/vulnerable-logs"

  # Intentionally NO kms_key_id (no encryption)
  # Intentionally NO retention_in_days (infinite retention)

  tags = {
    Name    = "cspm-lab-NAME_PLACEHOLDER-log-group"
    Purpose = "checkov-scan-target"
  }
}

# -----------------------------------------------------------------------------
# FINDING 6: SNS Topic — no encryption
# Checkov: CKV_AWS_26 — Ensure all data stored in the SNS topic is encrypted
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "vulnerable_topic" {
  name = "cspm-lab-NAME_PLACEHOLDER-unencrypted-topic"

  # Intentionally NO kms_master_key_id (no encryption)

  tags = {
    Name    = "cspm-lab-NAME_PLACEHOLDER-topic"
    Purpose = "checkov-scan-target"
  }
}

# -----------------------------------------------------------------------------
# FINDING 7: SQS Queue — no encryption
# Checkov: CKV_AWS_27 — Ensure all data stored in the SQS queue is encrypted
# -----------------------------------------------------------------------------

resource "aws_sqs_queue" "vulnerable_queue" {
  name = "cspm-lab-NAME_PLACEHOLDER-unencrypted-queue"

  # Intentionally NO sqs_managed_sse_enabled (no encryption)
  # Intentionally NO kms_master_key_id

  tags = {
    Name    = "cspm-lab-NAME_PLACEHOLDER-queue"
    Purpose = "checkov-scan-target"
  }
}
