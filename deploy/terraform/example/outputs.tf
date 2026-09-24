output "role_arn" {
  description = "ARN of the IRSA role, as set on the chart's ServiceAccount."
  value       = aws_iam_role.ctaudit.arn
}

output "policy_arns" {
  description = "Reader policy ARNs attached to the role, by log bucket key."
  value       = { for k, m in module.reader : k => m.policy_arn }
}

output "namespace" {
  description = "Namespace of the release."
  value       = helm_release.ctaudit.namespace
}

output "release_name" {
  description = "Helm release name."
  value       = helm_release.ctaudit.name
}
