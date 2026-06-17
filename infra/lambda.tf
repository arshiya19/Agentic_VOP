# --- Lambda Function: NVD Sync ---

variable "lambda_s3_key" {
  description = "S3 key for the Lambda deployment artifact (set by CI/CD)"
  type        = string
  default     = "nvd-sync/latest/lambda.zip"
}

resource "aws_lambda_function" "nvd_sync" {
  function_name = "sisyfix-${var.env}-nvd-sync"
  description   = "Periodically syncs NVD vulnerability feed data to DynamoDB"

  role = aws_iam_role.lambda_execution.arn

  s3_bucket = aws_s3_bucket.lambda_artifacts.id
  s3_key    = var.lambda_s3_key

  handler = "lambdas.nvd_sync.handler.lambda_handler"
  runtime = "python3.12"

  timeout     = 300
  memory_size = var.env == "prod" ? 512 : 256

  reserved_concurrent_executions = 1

  environment {
    variables = {
      ENVIRONMENT          = var.env
      INTELLIGENCE_TABLE   = aws_dynamodb_table.intelligence.name
      SSM_NVD_API_KEY_NAME = aws_ssm_parameter.nvd_api_key.name
    }
  }

  tags = {
    Component = "nvd-sync"
  }
}
