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

variable "slack_webhook_url" {
  description = "Falcosidekick Slack webhook (optional)"
  type        = string
  default     = ""
}