# ------------------------------------------------------------------------------
# Security Group for the build EC2 instance
# ------------------------------------------------------------------------------
# No inbound rules. Access is exclusively via SSM Session Manager (which works
# over the SSM agent's outbound connection — no open ports required). Egress is
# open so the build can pull base layers, reach ECR, and reach Fulcio/Rekor for
# keyless signing/verification.

resource "aws_security_group" "build" {
  name        = "${local.name}-sg"
  description = "Build box for hardened base images - no inbound, SSM-only access"
  vpc_id      = aws_vpc.main.id

  egress {
    description      = "All outbound traffic (base layers, ECR, Fulcio/Rekor, mirrors)"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${local.name}-sg"
  }
}
