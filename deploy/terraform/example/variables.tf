variable "region" {
  description = "AWS region of the EKS cluster."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.region))
    error_message = "region must be an AWS region such as us-east-1."
  }
}

variable "aws_profile" {
  description = "AWS shared config profile for the providers and `aws eks get-token`. Empty uses the default credential chain."
  type        = string
  default     = ""
}

variable "cluster_name" {
  description = "Name of the EKS cluster to install ctaudit into. It must have an IAM OIDC provider."
  type        = string

  validation {
    condition     = can(regex("^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$", var.cluster_name))
    error_message = "cluster_name must be a valid EKS cluster name."
  }
}

variable "namespace" {
  description = "Kubernetes namespace for the release."
  type        = string
  default     = "ctaudit"
}

variable "create_namespace" {
  description = "Create the namespace when it does not exist."
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Helm release name. The chart names its objects after it."
  type        = string
  default     = "ctaudit"
}

variable "service_account_name" {
  description = "Name of the ServiceAccount the chart creates. The IRSA trust policy allows only this name in var.namespace."
  type        = string
  default     = "ctaudit"
}

variable "role_name" {
  description = "Name of the IRSA role the pods assume. Empty uses ctaudit-<cluster_name>, so installs into two clusters in one account do not collide. Reader policies are named <role name>-<log_buckets key>."
  type        = string
  default     = ""

  validation {
    condition     = var.role_name == "" || can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.role_name))
    error_message = "role_name must be empty or 1-64 characters of letters, digits, and +=,.@_-."
  }
}

variable "log_buckets" {
  description = <<-EOT
    Log buckets the scanners read, keyed by a short name used in the policy
    name. log_prefix is the prefix before AWSLogs/ (empty when there is none).
    kms_key_arn is needed only for SSE-KMS encrypted CloudTrail logs.
  EOT
  type = map(object({
    name        = string
    log_prefix  = optional(string, "")
    kms_key_arn = optional(string, "")
  }))

  validation {
    condition     = length(var.log_buckets) > 0
    error_message = "log_buckets needs at least one bucket."
  }

  validation {
    condition     = alltrue([for k, b in var.log_buckets : can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", b.name))])
    error_message = "Each log_buckets name must be a valid S3 bucket name."
  }

  validation {
    condition     = alltrue([for k, b in var.log_buckets : can(regex("^[a-z0-9-]{1,32}$", k))])
    error_message = "log_buckets keys must be 1-32 lowercase letters, digits, or hyphens; they become part of the policy names."
  }
}

variable "image_repository" {
  description = "Container image repository for ctaudit, e.g. <account>.dkr.ecr.<region>.amazonaws.com/ctaudit."
  type        = string

  validation {
    condition     = length(trimspace(var.image_repository)) > 0
    error_message = "image_repository is required."
  }
}

variable "image_tag" {
  description = "Container image tag. Empty uses the chart's appVersion."
  type        = string
  default     = "0.2.0"
}

variable "bucket" {
  description = "Default log bucket for every scanner. A scanner can override it."
  type        = string
  default     = ""
}

variable "bucket_region" {
  description = "Region of the log buckets. Empty uses var.region."
  type        = string
  default     = ""

  validation {
    condition     = var.bucket_region == "" || can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.bucket_region))
    error_message = "bucket_region must be empty or an AWS region such as us-east-1."
  }
}

variable "accounts" {
  description = "Default AWS account IDs to scan, as strings."
  type        = list(string)

  validation {
    condition     = alltrue([for a in var.accounts : can(regex("^[0-9]{12}$", a))])
    error_message = "Each account must be a 12-digit AWS account ID in quotes."
  }
}

variable "regions" {
  description = "Default AWS regions to scan."
  type        = list(string)

  validation {
    condition     = alltrue([for r in var.regions : can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", r))])
    error_message = "Each region must be an AWS region such as us-east-1."
  }
}

variable "scanners" {
  description = "One ctaudit serve Deployment per entry. Unset fields fall back to the chart and the defaults above."
  type = list(object({
    name       = string
    subcommand = string
    interval   = optional(string)
    lookback   = optional(string)
    bucket     = optional(string)
    accounts   = optional(list(string))
    regions    = optional(list(string))
    args       = optional(list(string))
    debug      = optional(bool)
    log_format = optional(string)
  }))

  validation {
    condition     = length(var.scanners) > 0
    error_message = "scanners needs at least one entry."
  }

  validation {
    condition     = alltrue([for s in var.scanners : contains(["cloudtrail", "elb"], s.subcommand)])
    error_message = "Each scanner subcommand must be cloudtrail or elb."
  }

  # The chart names each Deployment <fullname>-<scanner name>, and fullname
  # is at most 32 characters, so 30 keeps the name inside a 63-character label.
  validation {
    condition     = alltrue([for s in var.scanners : can(regex("^[a-z0-9]([-a-z0-9]{0,28}[a-z0-9])?$", s.name))])
    error_message = "Each scanner name must be a DNS label of at most 30 lowercase letters, digits, or hyphens."
  }

  validation {
    condition     = length(distinct([for s in var.scanners : s.name])) == length(var.scanners)
    error_message = "Scanner names must be unique."
  }

  validation {
    condition     = alltrue([for s in var.scanners : contains(["text", "json"], coalesce(s.log_format, "text"))])
    error_message = "Each scanner log_format must be text or json."
  }

  validation {
    condition = alltrue(flatten([for s in var.scanners : [
      for d in compact([s.interval, s.lookback]) : can(regex("^([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h))+$", d))
    ]]))
    error_message = "Each scanner interval and lookback must be a Go duration such as 15m or 24h."
  }

  validation {
    condition = alltrue(flatten([for s in var.scanners : [
      for a in coalesce(s.accounts, []) : can(regex("^[0-9]{12}$", a))
    ]]))
    error_message = "Each scanner account must be a 12-digit AWS account ID in quotes."
  }
}

variable "loki_url" {
  description = "Loki base URL. Empty disables Loki."
  type        = string
  default     = ""
}

variable "loki_tenant" {
  description = "Loki tenant (X-Scope-OrgID). Empty sends none."
  type        = string
  default     = ""
}

variable "loki_existing_secret" {
  description = "Name of an existing Secret in var.namespace with CTAUDIT_LOKI_TOKEN, or CTAUDIT_LOKI_USER and CTAUDIT_LOKI_PASSWORD. Credentials are never passed through Terraform, so they stay out of the state."
  type        = string
  default     = ""
}

variable "debug" {
  description = "Pass --debug to every scanner."
  type        = bool
  default     = false
}

variable "log_format" {
  description = "Debug log format: text or json."
  type        = string
  default     = "text"

  validation {
    condition     = contains(["text", "json"], var.log_format)
    error_message = "log_format must be text or json."
  }
}

variable "prometheus_release_label" {
  description = "Value of the release label your Prometheus Operator selects, e.g. kube-prometheus-stack. Empty leaves the ServiceMonitor and PrometheusRule off."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Mandatory tags: Owner, Department, Project, Application, ManagedBy."
  type        = map(string)

  validation {
    condition = alltrue([
      for key in ["Owner", "Department", "Project", "Application", "ManagedBy"] :
      contains(keys(var.tags), key)
    ])
    error_message = "tags must include Owner, Department, Project, Application, and ManagedBy."
  }
}
