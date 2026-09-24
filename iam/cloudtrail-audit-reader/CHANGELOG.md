# Changelog

All notable changes to this module are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]
### Added
- Validation for `log_bucket_name`, `kms_key_arn`, and `policy_name`.
- `policy_json` output with the rendered policy document.
- README with usage and terraform-docs tables, and a module CLAUDE.md.
### Changed
- Split the module into `versions.tf`, `variables.tf`, `locals.tf`, `main.tf`, and `outputs.tf`.
- The policy document moved from an `aws_iam_policy_document` data source to `policies/reader.json.tftpl`. The statements, Sids, and description are unchanged.
- ARNs use the current partition from `data.aws_partition` instead of a hard-coded `aws`.

## [1.0.0] - 2026-09-23
### Added
- `aws_iam_policy` with `s3:ListBucket` limited to `AWSLogs/`, `s3:GetObject` on log objects, and optional `kms:Decrypt` through S3.
- Inputs `log_bucket_name`, `log_prefix`, `kms_key_arn`, `policy_name`, and `tags`; output `policy_arn`.
