output "intelligence_table_arn" {
  description = "ARN of the DynamoDB Intelligence Table"
  value       = aws_dynamodb_table.intelligence.arn
}

output "intelligence_table_name" {
  description = "Name of the DynamoDB Intelligence Table"
  value       = aws_dynamodb_table.intelligence.name
}

output "sync_lambda_arn" {
  description = "ARN of the NVD Sync Lambda function"
  value       = aws_lambda_function.nvd_sync.arn
}

output "sync_lambda_function_name" {
  description = "Name of the NVD Sync Lambda function"
  value       = aws_lambda_function.nvd_sync.function_name
}
