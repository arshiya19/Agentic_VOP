terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Backend configuration is provided via -backend-config flag
    # using environment-specific .hcl files in backend/
    # Example: terraform init -backend-config=backend/dev.hcl
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "sisyfix"
      Environment = var.env
      ManagedBy   = "terraform"
    }
  }
}
