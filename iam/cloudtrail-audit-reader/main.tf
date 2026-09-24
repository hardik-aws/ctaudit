# Least-privilege IAM policy for ctaudit. The tool only lists and reads log
# objects under AWSLogs/; it never writes to the bucket or touches any other
# AWS resource. Attach the policy to whatever role or user runs the scan.

resource "aws_iam_policy" "reader" {
  name = var.policy_name
  # Changing the description replaces the policy, so it keeps its first wording.
  description = "Read-only access to CloudTrail logs for the ctaudit analyzer."

  # jsondecode/jsonencode checks the rendered template is valid JSON and
  # normalises its whitespace.
  policy = jsonencode(jsondecode(templatefile("${path.module}/policies/reader.json.tftpl", {
    bucket_arn  = local.bucket_arn
    logs_path   = local.logs_path
    kms_key_arn = var.kms_key_arn
  })))

  tags = var.tags
}
