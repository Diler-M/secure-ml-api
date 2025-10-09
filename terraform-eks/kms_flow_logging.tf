# Inputs
variable "vpc_id" {
  description = "VPC ID to enable Flow Logs on"
  type        = string
}

variable "kms_key_alias" {
  description = "Alias for the KMS key used to encrypt CloudWatch Logs"
  type        = string
  default     = "alias/flow-logs"
}

variable "flow_logs_log_group_name" {
  description = "Name of the CloudWatch Log Group for VPC Flow Logs"
  type        = string
  default     = "/aws/vpc/flow-logs"
}

variable "retention_days" {
  description = "CloudWatch Logs retention (days)"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to created resources"
  type        = map(string)
  default     = {
    Project = "secure-ml-api"
    Env     = "dev"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region"          "current" {}
data "aws_partition"       "current" {}

data "aws_kms_key" "flow_logs" {
  key_id = var.kms_key_alias
}


# CloudWatch Log Group (KMS)
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = var.flow_logs_log_group_name
  kms_key_id        = data.aws_kms_key.flow_logs.arn
  retention_in_days = var.retention_days
  tags              = var.tags
}

# IAM role for VPC Flow Logs -> CW Logs #
data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "vpc-flow-logs-to-cw"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "flow_logs_write" {
  statement {
    sid = "CWLogsWrite"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents"
    ]

    resources = [
      aws_cloudwatch_log_group.vpc_flow_logs.arn,
      "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "vpc-flow-logs-write"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_write.json
}


# VPC Flow Logs enable
resource "aws_flow_log" "vpc" {
  vpc_id               = var.vpc_id
  traffic_type         = "ALL"

  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow_logs.name
  iam_role_arn         = aws_iam_role.flow_logs.arn


  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  tags = var.tags
}
