variable "log_bucket_name" {
  description = "Name of the S3 bucket the logs are delivered to (CloudTrail or ELB access logs)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.log_bucket_name))
    error_message = "log_bucket_name must be a valid S3 bucket name."
  }
}

variable "log_prefix" {
  description = "Key prefix configured on the trail or load balancer, without slashes. Empty when logs go straight to AWSLogs/."
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = "ARN of the KMS key the trail encrypts logs with (SSE-KMS). Leave empty for SSE-S3."
  type        = string
  default     = ""

  validation {
    condition     = var.kms_key_arn == "" || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "kms_key_arn must be empty or a KMS key ARN."
  }
}

variable "policy_name" {
  description = "Name of the IAM policy. IAM names are unique per account, so give each instance its own name."
  type        = string
  default     = "ctaudit-cloudtrail-reader"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,128}$", var.policy_name))
    error_message = "policy_name must be 1-128 characters of letters, digits, and +=,.@_-."
  }
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
