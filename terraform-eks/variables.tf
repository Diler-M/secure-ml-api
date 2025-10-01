variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "eu-west-2"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "How many AZs to use (2 recommended)"
  type        = number
  default     = 2
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "secure-ml-eks"
}

variable "node_desired_size" {
  description = "Desired node count"
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum node count"
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum node count"
  type        = number
  default     = 4
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default = {
    Project = "secure-ml-api"
    Owner   = "platform"
    Env     = "dev"
  }
}
