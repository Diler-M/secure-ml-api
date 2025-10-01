############################
# Global / AWS
############################
variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "eu-west-2"
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default = {
    Project     = "secure-ml-api"
    Environment = "dev"
    ManagedBy   = "terraform"
  }
}

############################
# Networking
############################
variable "vpc_cidr" {
  description = "CIDR block for the EKS VPC"
  type        = string
  default     = "10.0.0.0/16"
}

############################
# EKS
############################
variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "secure-ml-eks"
}

variable "kubernetes_version" {
  description = "Kubernetes version for EKS control plane"
  type        = string
  default     = "1.29"
}

variable "node_desired_size" {
  description = "Desired number of nodes in the default node group"
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum number of nodes in the default node group"
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum number of nodes in the default node group"
  type        = number
  default     = 3
}

variable "node_instance_types" {
  description = "EC2 instance types for node group"
  type        = list(string)
  default     = ["t3.medium"]
}