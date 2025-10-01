# -------- Variables used by main.tf --------

variable "aws_region" {
  type        = string
  description = "AWS region to deploy to"
  default     = "us-east-1"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the EKS VPC"
  default     = "10.1.0.0/16"
}

variable "cluster_name" {
  type        = string
  description = "EKS cluster name"
  default     = "secure-ml-eks"
}

variable "tags" {
  type        = map(string)
  description = "Common tags to apply to all resources"
  default = {
    Project     = "secure-ml-api"
    Environment = "dev"
  }
}
