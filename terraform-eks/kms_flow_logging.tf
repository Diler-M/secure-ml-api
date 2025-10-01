########################################
# KMS + CloudWatch Logs + VPC Flow Logs
# (cycle-safe, Checkov-friendly)
########################################

# Shared data sources (used by both files)
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS key policy for CloudWatch Logs:
# - DOES NOT reference the log group resource (avoids cycle)
# - Constrained to your account, region, and specific log group name via encryption context
data "aws_iam_policy_document" "kms_cloudwatch_logs" {
  # Root permissions
  statement {
    sid     = "EnableIAMUserPermissions"
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # CW Logs service permissions with tight constraints
  statement {
    sid    = "AllowCloudWatchLogsUseOfKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/vpc/flow-logs"
      ]
    }
  }
}

resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_cloudwatch_logs.json
  tags                    = merge(var.tags, { Name = "cw-logs-kms" })
}

resource "aws_cloudwatch_log_group" "vpc_flow_with_kms" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  tags              = merge(var.tags, { Name = "vpc-flow-logs" })
}

# IAM role for VPC Flow Logs service
resource "aws_iam_role" "vpc_flow" {
  name = "vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowVPCFlowLogsToAssumeRole",
      Effect    = "Allow",
      Action    = "sts:AssumeRole",
      Principal = { Service = "vpc-flow-logs.${data.aws_region.current.name}.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "vpc-flow-role" })
}

# Least privilege to write to the specific log group
resource "aws_iam_role_policy" "vpc_flow" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid    = "AllowWriteToLogGroup",
      Effect = "Allow",
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      Resource = [
        aws_cloudwatch_log_group.vpc_flow_with_kms.arn,
        "${aws_cloudwatch_log_group.vpc_flow_with_kms.arn}:*"
      ]
    }]
  })
}

# VPC Flow Logs -> CloudWatch Logs (encrypted)
resource "aws_flow_log" "vpc" {
  vpc_id                    = aws_vpc.eks.id
  traffic_type              = "ALL"
  log_destination_type      = "cloud-watch-logs"
  cloud_watch_log_group_arn = aws_cloudwatch_log_group.vpc_flow_with_kms.arn
  iam_role_arn              = aws_iam_role.vpc_flow.arn

  tags = merge(var.tags, { Name = "vpc-flow-log" })
}