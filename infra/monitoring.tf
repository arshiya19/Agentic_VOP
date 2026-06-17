# --- Monitoring: CloudWatch Alarms + SNS Notifications ---

# SNS Topic for alarm notifications
resource "aws_sns_topic" "alerts" {
  name = "sisyfix-${var.env}-alerts"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Alarm 1: Lambda invocation errors (>0 for 2 consecutive 5-min periods)
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "sisyfix-${var.env}-lambda-errors"
  alarm_description   = "Fires when the NVD Sync Lambda produces any errors over 2 consecutive periods"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0

  dimensions = {
    FunctionName = "sisyfix-${var.env}-nvd-sync"
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Alarm 2: DLQ messages visible (>0 for 1 period)
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "sisyfix-${var.env}-dlq-messages-visible"
  alarm_description   = "Fires when the NVD Sync DLQ has any visible messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0

  dimensions = {
    QueueName = "sisyfix-${var.env}-nvd-sync-dlq"
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Alarm 3: GapHours custom metric (>24 for 1 hour)
resource "aws_cloudwatch_metric_alarm" "gap_hours" {
  alarm_name          = "sisyfix-${var.env}-gap-hours-exceeded"
  alarm_description   = "Fires when the sync gap exceeds 24 hours"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "GapHours"
  namespace           = "Sisyfix/NvdSync"
  period              = 3600
  statistic           = "Maximum"
  threshold           = 24

  dimensions = {
    Environment = var.env
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Alarm 4: Lambda duration (>250000ms for 1 period)
resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "sisyfix-${var.env}-lambda-duration-high"
  alarm_description   = "Fires when the NVD Sync Lambda duration exceeds 250 seconds"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Maximum"
  threshold           = 250000

  dimensions = {
    FunctionName = "sisyfix-${var.env}-nvd-sync"
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}
