# CLAUDE.md — deploy/terraform/example

## Purpose
Example root module that installs ctaudit serve on an EKS cluster. It creates the reader policies and the IRSA role, and installs the local Helm chart with the role ARN passed into `serviceAccount.roleArn`.

## File Map
- `versions.tf`: Terraform and provider minimum versions, the `aws` and `helm` provider blocks, and a commented-out backend. This is a root module, so the provider blocks belong here.
- `variables.tf`: inputs with validation.
- `main.tf`: EKS and OIDC lookups, `module.reader` per log bucket, the IAM role and attachments, the chart values, and `helm_release`.
- `policies/irsa-trust.json.tftpl`: the role's trust policy.
- `outputs.tf`: `role_arn`, `policy_arns`, `namespace`, and `release_name`.
- `terraform.tfvars.example`: a filled-in example; `terraform.tfvars` is git-ignored.
- `README.md`: prerequisites, usage, plus terraform-docs tables between the `BEGIN_TF_DOCS` markers.

## Key Design Decisions
- `log_buckets` is a map, so `module.reader` uses `for_each` and each policy is named `<role name>-<key>`.
- The trust policy requires both `sub = system:serviceaccount:<namespace>:<service_account_name>` and `aud = sts.amazonaws.com`. The chart's ServiceAccount name is set explicitly so it always matches.
- Chart values are built in `local.values` and passed with `yamlencode`. Scanner fields left null are omitted with `merge()`, so the chart's defaults apply.
- Loki credentials never pass through Terraform; only the name of an existing Secret does, so they stay out of the state.
- The helm provider authenticates with `aws eks get-token`, so no kubeconfig is needed.

## Inputs / Outputs
See the README tables. `image_repository`, `region`, `cluster_name`, `log_buckets`, `accounts`, `regions`, `scanners`, and `tags` are required.

## Conventions
- A new chart value is added to `local.values` and, if it is per scanner, to the `scanners` object type and the `merge()` list.
- Every change gets an entry under `[Unreleased]` in `CHANGELOG.md`, and the README tables are regenerated.

## Gotchas
- The role name defaults to `ctaudit-<cluster_name>`; a precondition fails if it exceeds 64 characters.
- Scanner names are limited to 30 characters because the chart names Deployments `<fullname>-<scanner>` inside a 63-character label.
- Changing `namespace` or `service_account_name` changes the trust policy subject; both must match what the chart renders.
- The cluster must already have an IAM OIDC provider.
- Do not run `terraform plan` or `terraform apply` from this repository.
