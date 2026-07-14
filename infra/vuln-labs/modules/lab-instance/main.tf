# =============================================================================
# Lab Instance Module
# =============================================================================
# Provisions a single EC2 instance with intentionally vulnerable applications.
# The `role` variable determines whether scanners are installed (scan-source)
# or left out (remediation playground).
#
# Includes an IAM instance profile so the EC2 can:
#   - Run Terraform to manage CSPM lab resources (S3 + SG)
#   - Communicate with AWS Systems Manager (for SA4 remote execution)
#   - Access Terraform state in S3 + DynamoDB lock table
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
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_vpc" "selected" {
  id      = var.vpc_id != "" ? var.vpc_id : null
  default = var.vpc_id == "" ? true : null
}

data "aws_caller_identity" "current" {}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# -----------------------------------------------------------------------------
# SSH Key Pair
# -----------------------------------------------------------------------------

resource "tls_private_key" "lab" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "lab" {
  key_name   = "${var.name_prefix}-key"
  public_key = tls_private_key.lab.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.lab.private_key_pem
  filename        = "${path.root}/${var.name_prefix}-key.pem"
  file_permission = "0400"
}

# -----------------------------------------------------------------------------
# IAM Role + Instance Profile
# Grants the EC2 instance permissions to:
#   - Manage CSPM lab resources (S3 buckets + Security Groups)
#   - Access Terraform state backend (S3 + DynamoDB)
#   - Communicate with SSM (for SA4 remote command execution)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "lab" {
  name = "${var.name_prefix}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-role"
    Role = var.role
  }
}

resource "aws_iam_instance_profile" "lab" {
  name = "${var.name_prefix}-profile"
  role = aws_iam_role.lab.name
}

# SSM Agent permissions (for SA4 remote execution)
resource "aws_iam_role_policy" "ssm" {
  name = "${var.name_prefix}-ssm"
  role = aws_iam_role.lab.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMAgent"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      }
    ]
  })
}

# Terraform state backend permissions (S3 + DynamoDB)
resource "aws_iam_role_policy" "terraform_state" {
  name = "${var.name_prefix}-tf-state"
  role = aws_iam_role.lab.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateS3"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.terraform_state_bucket}",
          "arn:aws:s3:::${var.terraform_state_bucket}/vuln-labs/cspm-lab/*"
        ]
      },
      {
        Sid    = "TerraformStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.terraform_lock_table}"
      }
    ]
  })
}

# CSPM Lab — S3 bucket management permissions
resource "aws_iam_role_policy" "cspm_s3" {
  name = "${var.name_prefix}-cspm-s3"
  role = aws_iam_role.lab.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CSPMLabS3"
        Effect = "Allow"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::cspm-lab-*",
          "arn:aws:s3:::cspm-lab-*/*"
        ]
      }
    ]
  })
}

# CSPM Lab — EC2 Security Group management permissions
resource "aws_iam_role_policy" "cspm_sg" {
  name = "${var.name_prefix}-cspm-sg"
  role = aws_iam_role.lab.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CSPMLabSGManage"
        Effect   = "Allow"
        Action   = "ec2:*"
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Security Group — Properly secured for lab operation
# Only opens ports actually needed for the instance role.
# -----------------------------------------------------------------------------

resource "aws_security_group" "lab" {
  name        = "${var.name_prefix}-sg"
  description = "Security group for ${var.name_prefix} lab instance"
  vpc_id      = data.aws_vpc.selected.id

  # SSH — restricted to operator (placeholder CIDR, override via tfvars if needed)
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Acceptable for dev/demo; tighten for production
  }

  # Scan server port — only on scan-source instances
  dynamic "ingress" {
    for_each = var.install_scan_server ? [1] : []
    content {
      description = "Scan server API"
      from_port   = var.scan_server_port
      to_port     = var.scan_server_port
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-sg"
    Role = var.role
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance
# -----------------------------------------------------------------------------

resource "aws_instance" "lab" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.lab.key_name
  vpc_security_group_ids = [aws_security_group.lab.id]
  iam_instance_profile   = aws_iam_instance_profile.lab.name

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    install_scanners       = var.install_scanners
    install_scan_server    = var.install_scan_server
    scan_server_port       = var.scan_server_port
    role                   = var.role
    name_prefix            = var.name_prefix
    aws_region             = var.aws_region
    terraform_state_bucket = var.terraform_state_bucket
    terraform_lock_table   = var.terraform_lock_table
  })

  tags = {
    Name = "${var.name_prefix}-instance"
    Role = var.role
  }
}
