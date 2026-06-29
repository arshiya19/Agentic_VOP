# =============================================================================
# Vulnerable Lab Environment — Single EC2 instance with intentionally
# vulnerable applications for scanner demonstration.
#
# Contains:
#   - Flask app with SQL injection (SAST — Semgrep)
#   - Node/Java project with Log4j dependency (SCA — Trivy FS)
#   - Docker image with outdated OpenSSL (Infra — Trivy Image)
#   - Misconfigured S3 bucket + open security group (CSPM — Checkov)
#
# Usage:
#   cd infra/vuln-labs
#   terraform init
#   terraform plan
#   terraform apply
#
# Destroy when done:
#   terraform destroy
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

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for the lab"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (t4g.micro is free-tier eligible for ARM)"
  type        = string
  default     = "t4g.micro"
}

variable "lab_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "vop-vuln-lab"
}

# -----------------------------------------------------------------------------
# SSH Key Pair (generated locally, no manual setup needed)
# -----------------------------------------------------------------------------

resource "tls_private_key" "lab" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "lab" {
  key_name   = "${var.lab_name}-key"
  public_key = tls_private_key.lab.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.lab.private_key_pem
  filename        = "${path.module}/lab-key.pem"
  file_permission = "0400"
}

# -----------------------------------------------------------------------------
# VPC / Security Group (intentionally open for CSPM demo)
# -----------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-sg"
  description = "INTENTIONALLY OPEN - Vulnerable lab for CSPM scanning demo"
  vpc_id      = data.aws_vpc.default.id

  # SSH from anywhere (CSPM finding: open SSH)
  ingress {
    description = "SSH open to world - intentional vuln for Checkov"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP from anywhere
  ingress {
    description = "HTTP open to world"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Flask app port
  ingress {
    description = "Flask app"
    from_port   = 5000
    to_port     = 5000
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
    Name        = "${var.lab_name}-sg"
    Environment = "lab"
    Purpose     = "vulnerability-scanning-demo"
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket (intentionally public — CSPM finding for Checkov)
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "vuln_bucket" {
  bucket        = "${var.lab_name}-public-bucket-${data.aws_vpc.default.id}"
  force_destroy = true

  tags = {
    Name        = "${var.lab_name}-public-bucket"
    Environment = "lab"
    Purpose     = "cspm-demo-intentionally-public"
  }
}

# Intentionally NO encryption, NO versioning, NO public access block
# These are all CSPM findings Checkov will detect.

# -----------------------------------------------------------------------------
# EC2 Instance with vulnerable apps
# -----------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "lab" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.lab.key_name
  vpc_security_group_ids = [aws_security_group.lab.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user-data.sh")

  tags = {
    Name        = "${var.lab_name}-instance"
    Environment = "lab"
    Purpose     = "vulnerability-scanning-demo"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_public_ip" {
  description = "Public IP of the lab instance"
  value       = aws_instance.lab.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.lab.id
}

output "ssh_command" {
  description = "SSH command to connect to the lab"
  value       = "ssh -i ${path.module}/lab-key.pem ubuntu@${aws_instance.lab.public_ip}"
}

output "s3_bucket" {
  description = "Intentionally misconfigured S3 bucket name"
  value       = aws_s3_bucket.vuln_bucket.bucket
}

output "security_group_id" {
  description = "Security group with open SSH (CSPM finding)"
  value       = aws_security_group.lab.id
}
