resource "aws_sqs_queue" "nvd_sync_dlq" {
  name                      = "sisyfix-${var.env}-nvd-sync-dlq"
  message_retention_seconds = 1209600 # 14 days
}
