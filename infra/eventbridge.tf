# --- EventBridge Schedule Rule: NVD Sync Trigger ---

resource "aws_cloudwatch_event_rule" "nvd_sync_schedule" {
  name                = "sisyfix-${var.env}-nvd-sync-schedule"
  description         = "Triggers the NVD Sync Lambda on a scheduled interval"
  schedule_expression = var.env == "prod" ? "rate(2 hours)" : "rate(6 hours)"

  tags = {
    Component = "nvd-sync"
  }
}

resource "aws_cloudwatch_event_target" "nvd_sync_target" {
  rule      = aws_cloudwatch_event_rule.nvd_sync_schedule.name
  target_id = "nvd-sync-lambda"
  arn       = aws_lambda_function.nvd_sync.arn

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 21600 # 6 hours
  }

  dead_letter_config {
    arn = aws_sqs_queue.nvd_sync_dlq.arn
  }
}

# Permission for EventBridge to invoke the Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.nvd_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.nvd_sync_schedule.arn
}
