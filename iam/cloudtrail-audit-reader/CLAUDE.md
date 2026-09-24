# CLAUDE.md — cloudtrail-audit-reader

## Purpose
Creates one least-privilege IAM policy that lets ctaudit read AWS logs (CloudTrail, or ELB access and connection logs) from one S3 bucket. It creates no role or attachment; callers attach `policy_arn` themselves.

## File Map
- `versions.tf`: Terraform and AWS provider minimum versions. No provider or backend blocks.
- `variables.tf`: inputs with validation.
- `locals.tf`: the partition lookup, the normalised `AWSLogs/` path, and the bucket ARN.
- `main.tf`: the `aws_iam_policy` resource, rendered from the template.
- `policies/reader.json.tftpl`: the policy document; the KMS statement is included only when `kms_key_arn` is set.
- `outputs.tf`: `policy_arn` and `policy_json`.
- `README.md`: usage, plus terraform-docs tables between the `BEGIN_TF_DOCS` markers.

## Key Design Decisions
- `s3:ListBucket` is limited by an `s3:prefix` condition to `[<prefix>/]AWSLogs/*`, matching ctaudit, which never lists the bucket root.
- `kms:Decrypt` is limited by `kms:ViaService = s3.*.amazonaws.com`, so it only works for S3 reads.
- The template output goes through `jsonencode(jsondecode(...))`, which fails on invalid JSON and normalises whitespace.
- ARNs use `data.aws_partition` so the module works outside the `aws` partition.

## Inputs / Outputs
See the README tables. `tags` must contain Owner, Department, Project, Application, and ManagedBy.

## Conventions
- Every change gets an entry under `[Unreleased]` in `CHANGELOG.md`.
- Regenerate the README tables with `terraform-docs -c ../../.terraform-docs.yml .` or the pre-commit hook.
- Keep the statement Sids and the policy description as they are: changing the description of an `aws_iam_policy` replaces it.

## Gotchas
- IAM policy names are unique per account; each instance needs its own `policy_name`.
- ELB access logs only support SSE-S3, so leave `kms_key_arn` empty for ELB buckets.
- Do not run `terraform plan` or `terraform apply` from this repository.
