variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "secure-ml-eks"
}

# Pick two AZ suffixes available in your region
variable "az_a_suffix" {
  description = "AZ suffix for the first AZ (e.g., a)"
  type        = string
  default     = "a"
}
variable "az_b_suffix" {
  description = "AZ suffix for the second AZ (e.g., b)"
  type        = string
  default     = "b"
}

variable "slack_webhook_url" {
  description = "Falcosidekick Slack webhook (optional)"
  type        = string
  default     = ""
}