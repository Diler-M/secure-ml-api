variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# Availability zone suffixes (keeps it multi-AZ without hardcoding)
variable "az_a_suffix" {
  description = "Suffix for AZ A"
  type        = string
  default     = "a"
}

variable "az_b_suffix" {
  description = "Suffix for AZ B"
  type        = string
  default     = "b"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "secure-ml-eks"
}

variable "node_desired_size" {
  description = "Desired size of node group"
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Min size of node group"
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Max size of node group"
  type        = number
  default     = 4
}

variable "node_instance_types" {
  description = "EC2 instance types for node group"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default     = {
    Project = "secure-ml-api"
    Owner   = "Diler"
  }
}