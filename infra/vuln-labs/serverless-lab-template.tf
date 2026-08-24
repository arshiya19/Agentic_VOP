# =============================================================================
# Serverless Lab — Intentionally Misconfigured AWS Lambda
# =============================================================================
# These resources are REAL and INTENTIONALLY VULNERABLE.
# Semgrep scans this file and the Lambda source for findings.
# SA4 (automated fixer) will remediate by editing these files and re-applying.
#
# IaC Findings (Terraform misconfigurations):
#   1.  Lambda — no VPC configuration
#   2.  Lambda — no dead letter queue
#   3.  Lambda — hardcoded secrets in environment variables
#   4.  Lambda — tracing not enabled (no X-Ray)
#   5.  Lambda — excessive timeout (900s)
#   6.  Lambda — no reserved concurrency limit
#   7.  IAM role — overly permissive assume role policy
#   8.  IAM policy — Action: * (wildcard actions)
#   9.  IAM policy — Resource: * (wildcard resources)
#   10. Lambda Function URL — auth type NONE (publicly accessible)
#   11. CloudWatch Log Group — no KMS encryption
#   12. CloudWatch Log Group — no retention period
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

# -----------------------------------------------------------------------------
# Lambda deployment package — zip the handler source
# -----------------------------------------------------------------------------

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

# -----------------------------------------------------------------------------
# FINDING 7: IAM Role — overly permissive assume role policy
# The Principal should be restricted to lambda.amazonaws.com only, but here
# it allows any AWS service to assume this role.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "lambda_role" {
  name = "serverless-lab-NAME_PLACEHOLDER-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "*" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "serverless-lab-NAME_PLACEHOLDER-role"
    Purpose = "serverless-scan-target"
  }
}

# -----------------------------------------------------------------------------
# FINDINGS 8 & 9: IAM Policy — Action: * and Resource: *
# Overly permissive policy attached to the Lambda execution role.
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "lambda_policy" {
  name        = "serverless-lab-NAME_PLACEHOLDER-policy"
  description = "INTENTIONALLY OVERLY PERMISSIVE - Serverless scan target"

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
    Name    = "serverless-lab-NAME_PLACEHOLDER-policy"
    Purpose = "serverless-scan-target"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# -----------------------------------------------------------------------------
# FINDINGS 1-6: Lambda Function — multiple misconfigurations
#   1. No vpc_config (no VPC)
#   2. No dead_letter_config (no DLQ)
#   3. Hardcoded secrets in environment variables
#   4. No tracing_config (no X-Ray)
#   5. Timeout set to maximum (900s)
#   6. No reserved_concurrent_executions (unbounded concurrency)
# -----------------------------------------------------------------------------

resource "aws_lambda_function" "vulnerable_handler" {
  function_name    = "serverless-lab-NAME_PLACEHOLDER-vuln-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 900
  memory_size      = 256

  # FINDING 3: Hardcoded secrets in environment variables
  environment {
    variables = {
      DB_HOST     = "prod-db.internal.corp.local"
      DB_PASSWORD = "SuperSecret123!"
      API_KEY     = "sk-prod-a1b2c3d4e5f6g7h8i9j0"
      STAGE       = "production"
    }
  }

  # Intentionally NO vpc_config (Finding 1)
  # Intentionally NO dead_letter_config (Finding 2)
  # Intentionally NO tracing_config (Finding 4)
  # Intentionally NO reserved_concurrent_executions (Finding 6)

  tags = {
    Name    = "serverless-lab-NAME_PLACEHOLDER-vuln-handler"
    Purpose = "serverless-scan-target"
  }
}

# -----------------------------------------------------------------------------
# FINDING 10: Lambda Function URL — publicly accessible, no auth
# -----------------------------------------------------------------------------

resource "aws_lambda_function_url" "public_url" {
  function_name      = aws_lambda_function.vulnerable_handler.function_name
  authorization_type = "NONE"
}

# -----------------------------------------------------------------------------
# FINDINGS 11 & 12: CloudWatch Log Group — no encryption, no retention
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name = "/aws/lambda/serverless-lab-NAME_PLACEHOLDER-vuln-handler"

  # Intentionally NO kms_key_id (Finding 11 — no encryption)
  # Intentionally NO retention_in_days (Finding 12 — infinite retention)

  tags = {
    Name    = "serverless-lab-NAME_PLACEHOLDER-logs"
    Purpose = "serverless-scan-target"
  }
}
