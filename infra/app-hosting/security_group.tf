# ------------------------------------------------------------------------------
# Security Group for EC2 Application Instance
# ------------------------------------------------------------------------------

resource "aws_security_group" "app" {
  name        = "sisyfix-${var.env}-app-sg"
  description = "Security group for the Sisyfix application EC2 instance"
  vpc_id      = aws_vpc.main.id

  # --- Ingress Rules ---

  # HTTP (Frontend)
  ingress {
    description      = "HTTP from anywhere (Frontend)"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # API
  ingress {
    description      = "API from anywhere"
    from_port        = 8000
    to_port          = 8000
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # SSH (restricted to GitHub Actions runner IPs)
  ingress {
    description = "SSH from GitHub Actions runners"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
  }

  # --- Egress Rules ---

  # All outbound traffic
  egress {
    description      = "All outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "sisyfix-${var.env}-app-sg"
  }
}
