# Inputs
variable "vpc_id" {
  description = "Single VPC ID to enable Flow Logs on (ignored if vpc_ids is non-empty)"
  type        = string
  default     = ""
}

variable "vpc_ids" {
  description = "List of VPC IDs to enable Flow Logs on (use this to cover ALL VPCs you manage here)"
  type        = list(string)
  default     = []
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
  description = "CloudWatch Logs retention (days) — must be >= 365 to satisfy CKV_AWS_338"
  type        = number
  default     = 400
}

variable "tags" {
  description = "Tags to apply to created resources"
  type        = map(string)
  default     = {
    Project = "secure-ml-api"
    Env     = "dev"
  }
}


# Data: no literals
data "aws_caller_identity" "current" {}
data "aws_region"          "current" {}
data "aws_partition"       "current" {}

# Look up the CMK by alias so no account ID/ARN is committed
data "aws_kms_key" "flow_logs" {
  key_id = var.kms_key_alias
}

# Determine target VPC(s)
locals {
  target_vpc_ids = length(var.vpc_ids) > 0 ? var.vpc_ids :
                   (var.vpc_id != "" ? [var.vpc_id] : [])
}

# Safety: ensure we don't apply with an empty list unintentionally
locals {
  enable_flow_logs = length(local.target_vpc_ids) > 0
}

# CloudWatch Log Group (KMS)
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  count             = local.enable_flow_logs ? 1 : 0
  name              = var.flow_logs_log_group_name
  kms_key_id        = data.aws_kms_key.flow_logs.arn
  retention_in_days = var.retention_days
  tags              = var.tags
}

# IAM role for VPC Flow Logs -> CW Logs
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
  count              = local.enable_flow_logs ? 1 : 0
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
      aws_cloudwatch_log_group.vpc_flow_logs[0].arn,
      "${aws_cloudwatch_log_group.vpc_flow_logs[0].arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  count  = local.enable_flow_logs ? 1 : 0
  name   = "vpc-flow-logs-write"
  role   = aws_iam_role.flow_logs[0].id
  policy = data.aws_iam_policy_document.flow_logs_write.json
}


# VPC Flow Logs enable
resource "aws_flow_log" "vpc" {
  for_each             = local.enable_flow_logs ? toset(local.target_vpc_ids) : toset([])
  vpc_id               = each.value
  traffic_type         = "ALL"

  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow_logs[0].name
  iam_role_arn         = aws_iam_role.flow_logs[0].arn


  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  tags = var.tags
}
