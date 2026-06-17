# SSM Parameter Store — NVD API key for gap recovery
# The value is set manually via the AWS Console or CLI after initial apply.

resource "aws_ssm_parameter" "nvd_api_key" {
  name        = "/sisyfix/${var.env}/nvd-api-key"
  description = "NVD API key used by the Sync Lambda for gap recovery requests"
  type        = "SecureString"
  value       = "PLACEHOLDER"

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Component = "nvd-sync"
  }
}
