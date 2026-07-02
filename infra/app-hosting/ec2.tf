# ------------------------------------------------------------------------------
# EC2 Instance, AMI Lookup, Key Pair, and TLS Key
# Requirements 1.1, 1.4, 1.7
# ------------------------------------------------------------------------------

# --- AMI Lookup: Ubuntu 22.04 LTS ARM64 (Canonical) ---

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-jammy-22.04-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --- TLS Private Key (RSA 4096) ---

resource "tls_private_key" "app" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# --- AWS Key Pair ---

resource "aws_key_pair" "app" {
  key_name   = "sisyfix-${var.env}-app-key"
  public_key = tls_private_key.app.public_key_openssh
}

# --- EC2 Instance ---

resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance.name
  key_name               = aws_key_pair.app.key_name

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/templates/user-data.sh", {
    aws_region        = var.aws_region
    env               = var.env
    github_repository = var.github_repository
  })
  user_data_replace_on_change = true

  tags = {
    Name = "sisyfix-${var.env}-app"
  }
}
