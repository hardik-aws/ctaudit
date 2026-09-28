# Deploying with Terraform

The repository has two Terraform pieces:

- [`iam/cloudtrail-audit-reader`](../iam/cloudtrail-audit-reader) is a module that creates the least-privilege IAM policy ctaudit needs to read one log bucket.
- [`deploy/terraform/example`](../deploy/terraform/example) is an example root module that uses the reader module, creates an IRSA role for EKS, and installs the [Helm chart](kubernetes.md#helm-chart).

You run `terraform init`, `plan`, and `apply` yourself, from your own workstation or pipeline, with credentials for the target account. Nothing in this repository runs them for you.

## Reader policy module

`iam/cloudtrail-audit-reader` creates one IAM policy for one bucket. It creates the policy only; attach it to the role or user that runs ctaudit. The policy allows:

- `s3:ListBucket` on the bucket, only for keys under `[<log_prefix>/]AWSLogs/`, so the bucket root is never listed
- `s3:GetObject` on objects under that same path
- `kms:Decrypt` on `kms_key_arn`, only through S3 (`kms:ViaService` `s3.*.amazonaws.com`), when you set it for SSE-KMS encrypted logs

CloudTrail, ELB access and connection logs, WAF logs, and VPC Flow Logs are all delivered under `AWSLogs/`, so one instance per bucket covers them. S3 server access logs are not: `ctaudit s3` lists the target prefix you configured, so grant that bucket its own policy statement for the target prefix instead of using this module as is (see [IAM](../README.md#iam)).

```hcl
module "ctaudit_reader" {
  source          = "./iam/cloudtrail-audit-reader"
  log_bucket_name = "org-cloudtrail-logs"
  kms_key_arn     = "arn:aws:kms:us-east-1:111122223333:key/..." # omit for SSE-S3
  policy_name     = "ctaudit-reader-cloudtrail"                  # unique per account
  tags = {
    Owner       = "platform-team"
    Department  = "engineering"
    Project     = "example-project"
    Application = "ctaudit"
    ManagedBy   = "terraform"
  }
}
```

| Input | Default | Meaning |
|---|---|---|
| `log_bucket_name` | required | Bucket the logs are delivered to |
| `tags` | required | Mandatory tags: `Owner`, `Department`, `Project`, `Application`, `ManagedBy` |
| `kms_key_arn` | `""` | KMS key for SSE-KMS logs; leave empty for SSE-S3 |
| `log_prefix` | `""` | Key prefix before `AWSLogs/`, without slashes |
| `policy_name` | `ctaudit-cloudtrail-reader` | IAM policy names are unique per account, so give each instance its own |

Outputs: `policy_arn` (attach it to the scanning role) and `policy_json` (the rendered document, for review or as an inline policy). The policy template is [`policies/reader.json.tftpl`](../iam/cloudtrail-audit-reader/policies/reader.json.tftpl), and the module's [README](../iam/cloudtrail-audit-reader/README.md) has the generated input and output tables.

## EKS example

[`deploy/terraform/example`](../deploy/terraform/example) creates:

- one reader policy per entry in `log_buckets`, from the module above, named `<role name>-<key>`
- an IAM role whose trust policy accepts only the cluster's OIDC provider, the `sts.amazonaws.com` audience, and the subject `system:serviceaccount:<namespace>:<service_account_name>`, with every reader policy attached. The role name defaults to `ctaudit-<cluster_name>`, so installs into two clusters in one account do not collide
- a `helm_release` of the local chart, with values built from the Terraform variables and the role ARN passed in as `serviceAccount.roleArn`

### Before you apply

- The cluster needs an IAM OIDC provider; the example looks it up and fails if it is missing.
- The nodes must be able to pull `image_repository` (for example `hardikaws/ctaudit`, or an ECR repository with a policy that allows the node role).
- Loki credentials never pass through Terraform, so they stay out of the state. Create a Secret with `CTAUDIT_LOKI_TOKEN`, or `CTAUDIT_LOKI_USER` and `CTAUDIT_LOKI_PASSWORD`, in the target namespace, and name it in `loki_existing_secret`.
- The ServiceMonitor and PrometheusRule need the Prometheus Operator CRDs. They are rendered only when `prometheus_release_label` is set.
- The `helm` provider gets a token with `aws eks get-token`, so the AWS CLI must be installed where Terraform runs.
- Add a backend in `versions.tf` before sharing the state.

### Main variables

| Variable | Default | Meaning |
|---|---|---|
| `region` | required | Region of the EKS cluster |
| `cluster_name` | required | EKS cluster to install into |
| `image_repository` | required | Container image repository |
| `image_tag` | `0.4.0` | Image tag; empty uses the chart's `appVersion` |
| `log_buckets` | required | Map of `{ name, log_prefix, kms_key_arn }` per bucket; the key is used in the policy name |
| `accounts`, `regions` | required | Default accounts and regions to scan |
| `bucket`, `bucket_region` | `""` | Default log bucket and its region (empty uses `region`) |
| `scanners` | required | List of `{ name, subcommand, interval, lookback, bucket, accounts, regions, args, debug, log_format }`; unset fields fall back to the chart defaults |
| `tags` | required | Mandatory tags |
| `namespace`, `create_namespace` | `ctaudit`, `true` | Kubernetes namespace |
| `release_name`, `service_account_name`, `role_name` | `ctaudit`, `ctaudit`, `""` | Names |
| `loki_url`, `loki_tenant`, `loki_existing_secret` | `""` | Loki settings |
| `prometheus_release_label` | `""` | Label value your Prometheus Operator selects; empty leaves ServiceMonitor and PrometheusRule off |
| `debug`, `log_format` | `false`, `text` | Debug logging for every scanner |
| `aws_profile` | `""` | Profile for the providers and `aws eks get-token` |

The example's [README](../deploy/terraform/example/README.md) has the full generated tables, and [`terraform.tfvars.example`](../deploy/terraform/example/terraform.tfvars.example) is a starting point. Outputs are `role_arn`, `policy_arns`, `namespace`, and `release_name`.

### Usage

```bash
cd deploy/terraform/example
cp terraform.tfvars.example terraform.tfvars   # then edit it; terraform.tfvars is git-ignored
terraform init
terraform plan
terraform apply
```

After the apply, check a scanner:

```bash
kubectl -n ctaudit logs deploy/ctaudit-cloudtrail
kubectl -n ctaudit port-forward svc/ctaudit-cloudtrail 8080:8080   # then open localhost:8080/report
```

Set `debug = true`, globally or inside one `scanners` entry, to see each listed prefix, object read, and tick decision in the pod log.
