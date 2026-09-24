output "policy_arn" {
  description = "ARN of the ctaudit reader policy. Attach it to the scanning role."
  value       = aws_iam_policy.reader.arn
}

output "policy_json" {
  description = "Rendered policy document, for review or for use as an inline policy."
  value       = aws_iam_policy.reader.policy
}
