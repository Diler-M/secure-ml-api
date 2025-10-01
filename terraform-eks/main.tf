############################
# Networking (VPC/Subnets) #
############################

resource "aws_vpc" "eks" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "eks-vpc" })
}

# Lock down the default security group (CKV2_AWS_12)
resource "aws_default_security_group" "default" {
  vpc_id                 = aws_vpc.eks.id
  revoke_rules_on_delete = true
  # No ingress/egress blocks -> fully restricted
  tags = merge(var.tags, { Name = "eks-default-sg-locked" })
}

# Public subnets (no auto-assign public IPs by default)
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = var.public_subnet_cidrs[0]
  map_public_ip_on_launch = false
  availability_zone       = "${var.aws_region}a"
  tags = merge(
    var.tags,
    { Name = "public-a", "kubernetes.io/role/elb" = "1" }
  )
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = var.public_subnet_cidrs[1]
  map_public_ip_on_launch = false
  availability_zone       = "${var.aws_region}b"
  tags = merge(
    var.tags,
    { Name = "public-b", "kubernetes.io/role/elb" = "1" }
  )
}

# Private subnets
resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = var.private_subnet_cidrs[0]
  map_public_ip_on_launch = false
  availability_zone       = "${var.aws_region}a"
  tags = merge(
    var.tags,
    { Name = "private-a", "kubernetes.io/role/internal-elb" = "1" }
  )
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = var.private_subnet_cidrs[1]
  map_public_ip_on_launch = false
  availability_zone       = "${var.aws_region}b"
  tags = merge(
    var.tags,
    { Name = "private-b", "kubernetes.io/role/internal-elb" = "1" }
  )
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-igw" })
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "eks-nat-eip" })
}

resource "aws_nat_gateway" "nat" {
  subnet_id     = aws_subnet.public_a.id
  allocation_id = aws_eip.nat_eip.id
  tags          = merge(var.tags, { Name = "eks-nat" })
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-public-rt" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-private-rt" })
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

############################
# Flow Logs + CloudWatch   #
############################

resource "aws_iam_role" "vpc_flow" {
  name = "${var.cluster_name}-vpc-flow-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Name = "vpc-flow-role" })
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "${var.cluster_name}-vpc-flow-policy"
  role = aws_iam_role.vpc_flow.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid     = "AllowCreateLogGroup",
        Effect  = "Allow",
        Action  = ["logs:CreateLogGroup"],
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid     = "AllowWriteToLogStreams",
        Effect  = "Allow",
        Action  = ["logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogStreams"],
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/vpc/flow-logs:log-stream:*"
      }
    ]
  })
}

############################
# KMS for CloudWatch Logs  #
############################

resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = merge(var.tags, { Name = "cw-logs-kms" })
}

data "aws_iam_policy_document" "kms_cloudwatch_logs" {
  statement {
    sid     = "EnableIAMUserPermissions"
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:Create*","kms:Describe*","kms:Enable*","kms:List*","kms:Put*",
      "kms:Update*","kms:Revoke*","kms:Disable*","kms:Get*","kms:Delete*",
      "kms:ScheduleKeyDeletion","kms:CancelKeyDeletion","kms:TagResource","kms:UntagResource"
    ]
    resources = [aws_kms_key.cloudwatch_logs.arn]
  }

  statement {
    sid    = "AllowCloudWatchLogsUseOfKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:DescribeKey"]
    resources = [aws_kms_key.cloudwatch_logs.arn]

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = [aws_cloudwatch_log_group.vpc_flow_with_kms.arn]
    }
  }
}

resource "aws_kms_key_policy" "cloudwatch_logs" {
  key_id = aws_kms_key.cloudwatch_logs.key_id
  policy = data.aws_iam_policy_document.kms_cloudwatch_logs.json
}

# Single log group (no duplicate resource). It depends on the key (kms_key_id),
# while the key policy depends on this log group (via ARN) — no cycle:
# key -> log group -> key policy
resource "aws_cloudwatch_log_group" "vpc_flow_with_kms" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  tags              = merge(var.tags, { Name = "vpc-flow-logs" })
}

resource "aws_cloudwatch_log_resource_policy" "allow_vpc_flow_to_use_log_group" {
  policy_name     = "${var.cluster_name}-vpc-flow-cw-policy"
  policy_document = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid      = "AllowVPCAccessToLogGroup",
      Effect   = "Allow",
      Action   = ["logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogStreams"],
      Resource = "${aws_cloudwatch_log_group.vpc_flow_with_kms.arn}:*",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.eks.id
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow_with_kms.name
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  traffic_type         = "ALL"
  tags                 = merge(var.tags, { Name = "vpc-flow-log" })
}

############################
# KMS for EKS Secrets      #
############################

resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = merge(var.tags, { Name = "eks-secrets-kms" })
}

data "aws_iam_policy_document" "kms_eks_secrets" {
  statement {
    sid     = "EnableIAMUserPermissions"
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:Create*","kms:Describe*","kms:Enable*","kms:List*","kms:Put*",
      "kms:Update*","kms:Revoke*","kms:Disable*","kms:Get*","kms:Delete*",
      "kms:ScheduleKeyDeletion","kms:CancelKeyDeletion","kms:TagResource","kms:UntagResource"
    ]
    resources = [aws_kms_key.eks_secrets.arn]
  }

  statement {
    sid    = "AllowEKSUseOfKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["eks.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:DescribeKey","kms:CreateGrant"]
    resources = [aws_kms_key.eks_secrets.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["eks.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key_policy" "eks_secrets" {
  key_id = aws_kms_key.eks_secrets.key_id
  policy = data.aws_iam_policy_document.kms_eks_secrets.json
}

############################
# EKS IAM & Cluster        #
############################

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Name = "eks-cluster-role" })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Name = "eks-node-role" })
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_ecr_ro" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    endpoint_public_access  = false
    endpoint_private_access = true
  }

  enabled_cluster_log_types = ["api","audit","authenticator","controllerManager","scheduler"]

  encryption_config {
    provider { key_arn = aws_kms_key.eks_secrets.arn }
    resources = ["secrets"]
  }

  tags = merge(var.tags, { Name = var.cluster_name })

  depends_on = [
    aws_kms_key_policy.eks_secrets,
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]
}

resource "aws_eks_node_group" "default" {
  cluster_name   = aws_eks_cluster.this.name
  node_role_arn  = aws_iam_role.eks_node.arn
  subnet_ids     = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  instance_types = var.instance_types

  scaling_config {
    desired_size = var.desired_size
    min_size     = var.min_size
    max_size     = var.max_size
  }

  ami_type  = "AL2_x86_64"
  disk_size = 20

  tags = merge(var.tags, { Name = "${var.cluster_name}-nodegroup" })
}