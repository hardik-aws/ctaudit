data "aws_partition" "current" {}

locals {
  # trim() drops any leading/trailing slashes so "logs", "logs/", and
  # "/logs/" all normalise to the same "logs/AWSLogs" path.
  log_prefix_trimmed = trim(var.log_prefix, "/")
  logs_path          = local.log_prefix_trimmed == "" ? "AWSLogs" : "${local.log_prefix_trimmed}/AWSLogs"
  bucket_arn         = "arn:${data.aws_partition.current.partition}:s3:::${var.log_bucket_name}"
}
