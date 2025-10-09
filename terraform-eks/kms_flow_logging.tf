# Locals & Data
locals {
  # You can change these defaults here or expose them as variables in variables.tf if you prefer.
  kms_key_alias            = "alias/flow-logs"
  flow_logs_log_group_name = "/aws/vpc/flow-logs"
  retention_days           = 400  # ≥ 365 to satisfy CKV_AWS_338
}

# Look up KMS key by alias (no ARNs/account IDs committed)
data "aws_kms_key" "flow_logs" {
  key_id = local.kms_key_alias
}

# CloudWatch Log Group (KMS)
resource "aws_cloudwatch_log_group" "eks_vpc_flow_logs" {
  name              = local.flow_logs_log_group_name
  kms_key_id        = data.aws_kms_key.flow_logs.arn
  retention_in_days = local.retention_days
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

resource "aws_iam_role" "eks_vpc_flow_logs" {
  name               = "eks-vpc-flow-logs-to-cw"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "flow_logs_write" {
  statement {
    sid     = "CWLogsWrite"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents"
    ]
    resources = [
      aws_cloudwatch_log_group.eks_vpc_flow_logs.arn,
      "${aws_cloudwatch_log_group.eks_vpc_flow_logs.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "eks_vpc_flow_logs" {
  name   = "eks-vpc-flow-logs-write"
  role   = aws_iam_role.eks_vpc_flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_write.json
}

# VPC Flow Logs enable
resource "aws_flow_log" "eks_vpc" {
  vpc_id               = aws_vpc.eks.id
  traffic_type         = "ALL"

  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.eks_vpc_flow_logs.name
  iam_role_arn         = aws_iam_role.eks_vpc_flow_logs.arn


  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  tags = var.tags

  depends_on = [
    aws_cloudwatch_log_group.eks_vpc_flow_logs,
    aws_iam_role_policy.eks_vpc_flow_logs
  ]
}