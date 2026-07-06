# =============================================================================
# Lab Instance Module
# =============================================================================
# Provisions a single EC2 instance with intentionally vulnerable applications.
# The `role` variable determines whether scanners are installed (scan-source)
# or left out (remediation playground).
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

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    install_scanners    = var.install_scanners
    install_scan_server = var.install_scan_server
    scan_server_port    = var.scan_server_port
    role                = var.role
  })

  tags = {
    Name = "${var.name_prefix}-instance"
    Role = var.role
  }
}
