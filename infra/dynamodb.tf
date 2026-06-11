resource "aws_dynamodb_table" "intelligence" {
  name         = "sisyfix-${var.env}-vulnerability-intelligence"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "pk"
  range_key = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = var.env == "prod"
  }

  deletion_protection_enabled = var.env == "prod"

  server_side_encryption {
    enabled     = true
    kms_key_arn = null # Uses AWS-managed aws/dynamodb key
  }
}
