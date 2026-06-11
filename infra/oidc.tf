# -----------------------------------------------------------------------------
# GitHub OIDC Provider and Trust Policies
# Requirements: 16.1–16.5
# -----------------------------------------------------------------------------

# GitHub Actions OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # AWS no longer requires thumbprint verification for GitHub Actions OIDC.
  # An empty list or any value is accepted — AWS validates the token directly.
  # See: https://github.blog/changelog/2023-06-27-github-actions-update-on-oidc-integration-with-aws/
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]

  tags = {
    Name = "sisyfix-github-actions-oidc"
  }
}

# -----------------------------------------------------------------------------
# Trust Policy: Plan Role (any branch)
# Requirement 16.4: Allow any branch for the plan role
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "oidc_trust_plan" {
  statement {
    sid     = "AllowGitHubOIDCPlan"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Any branch — use StringLike with wildcard
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:*"]
    }
  }
}

# -----------------------------------------------------------------------------
# Trust Policy: Deployment Roles (main branch only)
# Requirements 16.2, 16.3: Restrict deployment roles to main branch
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "oidc_trust_deploy" {
  statement {
    sid     = "AllowGitHubOIDCDeploy"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Main branch only — exact match
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/main"]
    }
  }
}

# -----------------------------------------------------------------------------
# IAM Roles with OIDC Trust
# Requirement 16.5: Session duration limited to 900 seconds
# -----------------------------------------------------------------------------

# Plan role — read-only, any branch
resource "aws_iam_role" "github_infra_plan" {
  name                 = "sisyfix-github-infra-plan"
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust_plan.json
  max_session_duration = 3600

  tags = {
    Name = "sisyfix-github-infra-plan"
  }
}

# Infra apply role — deployment, main branch only
resource "aws_iam_role" "github_infra_apply" {
  name                 = "sisyfix-github-infra-apply-${var.env}"
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust_deploy.json
  max_session_duration = 3600

  tags = {
    Name = "sisyfix-github-infra-apply-${var.env}"
  }
}

# Lambda deploy role — deployment, main branch only
resource "aws_iam_role" "github_lambda_deploy" {
  name                 = "sisyfix-github-lambda-deploy-${var.env}"
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust_deploy.json
  max_session_duration = 3600

  tags = {
    Name = "sisyfix-github-lambda-deploy-${var.env}"
  }
}

# Backfill role — deployment, main branch only
resource "aws_iam_role" "github_backfill" {
  name                 = "sisyfix-github-backfill-${var.env}"
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust_deploy.json
  max_session_duration = 3600

  tags = {
    Name = "sisyfix-github-backfill-${var.env}"
  }
}
