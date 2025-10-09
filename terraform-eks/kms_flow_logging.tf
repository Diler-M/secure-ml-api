# Locals
locals {
  flow_logs_log_group_name = "/aws/vpc/flow-logs"
  retention_days           = 400  # ≥ 365 to satisfy CKV_AWS_338
  logs_service_principal   = "logs.${data.aws_region.current.name}.amazonaws.com"
  account_root_arn         = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  kms_key_arn_wildcard     = "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
}

# KMS CMK dedicated for VPC Flow Logs
data "aws_iam_policy_document" "kms_flow_logs" {
  statement {
    sid     = "EnableAccountAdminForThisKey"
    effect  = "Allow"
    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ]
    principals {
      type        = "AWS"
      identifiers = [local.account_root_arn]
    }
    resources = [local.kms_key_arn_wildcard]
  }

  # Allow CloudWatch Logs service to use the key for encryption
  statement {
    sid    = "AllowCloudWatchLogsUseOfKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = [local.logs_service_principal]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant"
    ]
    resources = [local.kms_key_arn_wildcard]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.logs_service_principal]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "flow_logs" {
  description             = "KMS key for VPC Flow Logs (CloudWatch Logs encryption)"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_flow_logs.json
  tags                    = merge(var.tags, { Name = "flow-logs-kms" })
}

resource "aws_kms_alias" "flow_logs" {
  name          = "alias/flow-logs"
  target_key_id = aws_kms_key.flow_logs.id
}
# CloudWatch Log Group (KMS)
resource "aws_cloudwatch_log_group" "eks_vpc_flow_logs" {
  name              = local.flow_logs_log_group_name
  kms_key_id        = aws_kms_key.flow_logs.arn
  retention_in_days = local.retention_days
  tags              = var.tags

  depends_on = [aws_kms_alias.flow_logs]
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

  # Optional: tweak if you like
  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  tags = var.tags

  depends_on = [
    aws_cloudwatch_log_group.eks_vpc_flow_logs,
    aws_iam_role_policy.eks_vpc_flow_logs
  ]
}