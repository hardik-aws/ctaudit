# Example root module: creates the IRSA role ctaudit reads logs with and
# installs the Helm chart with that role wired into its ServiceAccount.

data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_iam_openid_connect_provider" "this" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

locals {
  oidc_host     = replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
  monitored     = var.prometheus_release_label != ""
  role_name     = var.role_name != "" ? var.role_name : "ctaudit-${var.cluster_name}"
  bucket_region = var.bucket_region != "" ? var.bucket_region : var.region
}

# One least-privilege reader policy per log bucket. ELB logs use the same
# AWSLogs/ layout as CloudTrail, so the module covers both.
module "reader" {
  source   = "../../../iam/cloudtrail-audit-reader"
  for_each = var.log_buckets

  log_bucket_name = each.value.name
  log_prefix      = each.value.log_prefix
  kms_key_arn     = each.value.kms_key_arn
  policy_name     = "${local.role_name}-${each.key}"
  tags            = var.tags
}

resource "aws_iam_role" "ctaudit" {
  name        = local.role_name
  description = "IRSA role for ctaudit serve: read-only access to log buckets."

  # Only the chart's ServiceAccount in this namespace can assume the role.
  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/policies/irsa-trust.json.tftpl", {
    oidc_provider_arn = data.aws_iam_openid_connect_provider.this.arn
    oidc_host         = local.oidc_host
    subject           = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
  })))

  tags = var.tags

  lifecycle {
    precondition {
      condition     = length(local.role_name) <= 64
      error_message = "The role name ctaudit-<cluster_name> is longer than 64 characters; set role_name."
    }
  }
}

resource "aws_iam_role_policy_attachment" "reader" {
  for_each = module.reader

  role       = aws_iam_role.ctaudit.name
  policy_arn = each.value.policy_arn
}

locals {
  # Only set fields go to the chart, so its own defaults apply to the rest.
  scanners = [
    for s in var.scanners : merge(
      { name = s.name, subcommand = s.subcommand },
      s.interval == null ? {} : { interval = s.interval },
      s.lookback == null ? {} : { lookback = s.lookback },
      s.bucket == null ? {} : { bucket = s.bucket },
      s.accounts == null ? {} : { accounts = s.accounts },
      s.regions == null ? {} : { regions = s.regions },
      s.args == null ? {} : { args = s.args },
      s.debug == null ? {} : { debug = s.debug },
      s.log_format == null ? {} : { logFormat = s.log_format },
    )
  ]

  values = {
    image = {
      repository = var.image_repository
      tag        = var.image_tag
    }
    serviceAccount = {
      create  = true
      name    = var.service_account_name
      roleArn = aws_iam_role.ctaudit.arn
    }
    aws = {
      bucket       = var.bucket
      bucketRegion = local.bucket_region
      accounts     = var.accounts
      regions      = var.regions
    }
    loki = {
      url            = var.loki_url
      tenant         = var.loki_tenant
      existingSecret = var.loki_existing_secret
    }
    scanners  = local.scanners
    debug     = var.debug
    logFormat = var.log_format
    serviceMonitor = {
      enabled = local.monitored
      labels  = local.monitored ? { release = var.prometheus_release_label } : {}
    }
    prometheusRule = {
      enabled = local.monitored
      labels  = local.monitored ? { release = var.prometheus_release_label } : {}
    }
  }
}

resource "helm_release" "ctaudit" {
  name             = var.release_name
  chart            = "${path.module}/../../helm/ctaudit"
  namespace        = var.namespace
  create_namespace = var.create_namespace
  values           = [yamlencode(local.values)]

  # The role and its policies must exist before the pods first call S3.
  depends_on = [aws_iam_role_policy_attachment.reader]
}
