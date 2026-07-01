# ------------------------------------------------------------------------------
# SSM Parameter Store: App Secrets, SSH Key, and EC2 Public IP
# Requirements 3.1, 1.4, 10.6
# ------------------------------------------------------------------------------

# --- Locals: Secret Definitions ---

locals {
  # Required app secrets — initial value is a placeholder; operators set real values via Console/CLI
  required_app_secrets = {
    "AGENTIC_VOP_SUPABASE_URL"         = "CHANGE_ME"
    "AGENTIC_VOP_SUPABASE_SERVICE_KEY" = "CHANGE_ME"
    "OPENAI_API_KEY"                   = "CHANGE_ME"
    "SECRETS_ENCRYPTION_KEY"           = "CHANGE_ME"
  }

  # Optional app secrets — initial value is a placeholder; operators set values if needed
  optional_app_secrets = {
    "ANTHROPIC_API_KEY"       = "PLACEHOLDER"
    "GOOGLE_API_KEY"          = "PLACEHOLDER"
    "TENABLE_ACCESS_KEY"      = "PLACEHOLDER"
    "TENABLE_SECRET_KEY"      = "PLACEHOLDER"
    "GITHUB_TOKEN"            = "PLACEHOLDER"
    "NVD_API_KEY"             = "PLACEHOLDER"
    "INTELLIGENCE_TABLE_NAME" = "sisyfix-prod-vulnerability-intelligence"
    "INTELLIGENCE_AWS_REGION" = "us-east-1"
    "INTELLIGENCE_ENABLED"    = "true"
    "LLM_PARALLEL_WORKERS"    = "5"
    "MAX_SYNC_CACHE_MISSES"   = "10"
    "VITE_SUPABASE_URL"       = "PLACEHOLDER"
    "VITE_SUPABASE_ANON_KEY"  = "PLACEHOLDER"
    "VITE_API_BASE_URL"       = "PLACEHOLDER"
    "VITE_USER_API_KEY"       = "PLACEHOLDER"
    "VITE_ADMIN_API_KEY"      = "PLACEHOLDER"
    "VITE_BYPASS_AUTH"        = "false"
  }
}

# =============================================================================
# 1. REQUIRED APP SECRETS (SecureString, /sisyfix/{env}/app/{SECRET_NAME})
# =============================================================================

resource "aws_ssm_parameter" "required_secret" {
  for_each = local.required_app_secrets

  name  = "/sisyfix/${var.env}/app/${each.key}"
  type  = "SecureString"
  value = each.value

  description = "Required app secret: ${each.key}"

  tags = {
    Component = "app-hosting"
    Secret    = "required"
  }

  lifecycle {
    ignore_changes = [value]
  }
}

# =============================================================================
# 2. OPTIONAL APP SECRETS (SecureString, /sisyfix/{env}/app/{SECRET_NAME})
# =============================================================================

resource "aws_ssm_parameter" "optional_secret" {
  for_each = local.optional_app_secrets

  name      = "/sisyfix/${var.env}/app/${each.key}"
  type      = "SecureString"
  value     = each.value
  overwrite = true

  description = "Optional app secret: ${each.key}"

  tags = {
    Component = "app-hosting"
    Secret    = "optional"
  }

  lifecycle {
    ignore_changes = [value]
  }
}

# =============================================================================
# 3. SSH PRIVATE KEY (SecureString, /sisyfix/{env}/ec2/ssh-private-key)
# =============================================================================

resource "aws_ssm_parameter" "ssh_private_key" {
  name  = "/sisyfix/${var.env}/ec2/ssh-private-key"
  type  = "SecureString"
  value = tls_private_key.app.private_key_pem

  description = "SSH private key for EC2 instance access (RSA 4096)"

  tags = {
    Component = "app-hosting"
    Secret    = "infrastructure"
  }
}

# =============================================================================
# 4. EC2 PUBLIC IP (String, /sisyfix/{env}/ec2/public-ip)
# =============================================================================

resource "aws_ssm_parameter" "ec2_public_ip" {
  name  = "/sisyfix/${var.env}/ec2/public-ip"
  type  = "String"
  value = aws_instance.app.public_ip

  description = "EC2 instance public IPv4 address (written by Terraform)"

  tags = {
    Component = "app-hosting"
    Secret    = "infrastructure"
  }
}
