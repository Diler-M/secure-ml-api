############################################################
# CloudWatch Logs + KMS for VPC Flow Logs
############################################################

# Required identity/region data
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS policy for CloudWatch Logs
data "aws_iam_policy_document" "kms_cloudwatch_logs" {
  # Admin (resource-scoped to keys in this account/region)
  statement {
    sid     = "EnableAccountAdminForThisKey"
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
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
    resources = ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"]
  }

  # Allow CloudWatch Logs service to use the key
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
      "kms:DescribeKey",
      "kms:CreateGrant"
    ]
    resources = ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"]

    # Keep grants constrained to AWS resources
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
    # Constrain to our account
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
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

# IAM role to allow VPC Flow Logs service to write to CWL
resource "aws_iam_role" "vpc_flow" {
  name = "vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Name = "vpc-flow-logs-role" })
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "WriteToCloudWatchLogs",
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        Resource = "${aws_cloudwatch_log_group.vpc_flow_with_kms.arn}:*"
      }
    ]
  })
}

# VPC Flow Logs -> CloudWatch Logs
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.eks.id
  log_destination      = aws_cloudwatch_log_group.vpc_flow_with_kms.arn
  log_destination_type = "cloud-watch-logs"
  iam_role_arn         = aws_iam_role.vpc_flow.arn   # <- replaced deliver_logs_permission_arn
  traffic_type         = "ALL"

  tags = merge(var.tags, { Name = "vpc-flow-logs" })
}
