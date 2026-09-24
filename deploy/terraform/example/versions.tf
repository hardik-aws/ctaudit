terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 3.0"
    }
  }

  # Add your own backend, for example:
  # backend "s3" {
  #   bucket         = "my-terraform-state"
  #   key            = "ctaudit/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile == "" ? null : var.aws_profile
}

# The Helm provider reaches the cluster with a short-lived token from
# `aws eks get-token`, so no kubeconfig file is needed.
provider "helm" {
  kubernetes = {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = concat(
        ["eks", "get-token", "--cluster-name", var.cluster_name, "--region", var.region],
        var.aws_profile == "" ? [] : ["--profile", var.aws_profile],
      )
    }
  }
}
