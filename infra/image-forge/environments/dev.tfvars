env        = "dev"
aws_region = "us-east-1"

# GitHub repo whose Actions OIDC identity is trusted to sign images (gated to
# main). Change this single value if/when the repo migrates to a new owner,
# then re-apply — and update the verification identity in the signing design.
github_repository = "arshiya19/Agentic_VOP"

# VPC CIDR reuses 10.1.0.0/16 — freed by deleting the manual VOP-vpc-adhoc VPC.
vpc_cidr           = "10.1.0.0/16"
public_subnet_cidr = "10.1.1.0/24"

# Build box sizing — ARM64 Graviton, with EBS headroom for image layers.
instance_type = "t4g.medium"
volume_size   = 40

# Test publish target. IMMUTABLE tags model a real supply chain; flip to
# MUTABLE only if rapid re-tagging during manual iteration gets in the way.
ecr_repository_name      = "sisyfix-hardened-base-test"
ecr_image_tag_mutability = "IMMUTABLE"
ecr_untagged_expire_days = 7
