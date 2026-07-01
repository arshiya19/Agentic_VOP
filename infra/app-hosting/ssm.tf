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

  # Optional app secrets — initial value is empty; operators set values if needed
  optional_app_secrets = {
    "ANTHROPIC_API_KEY"       = ""
    "GOOGLE_API_KEY"          = ""
    "TENABLE_ACCESS_KEY"      = ""
    "TENABLE_SECRET_KEY"      = ""
    "GITHUB_TOKEN"            = ""
    "NVD_API_KEY"             = ""
    "INTELLIGENCE_TABLE_NAME" = ""
    "INTELLIGENCE_AWS_REGION" = ""
    "VITE_SUPABASE_URL"       = ""
    "VITE_SUPABASE_ANON_KEY"  = ""
    "VITE_API_BASE_URL"       = ""
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

  name  = "/sisyfix/${var.env}/app/${each.key}"
  type  = "SecureString"
  value = each.value

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
