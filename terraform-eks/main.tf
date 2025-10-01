terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data sources used in KMS key policies
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -------------------------------
# VPC and Networking
# -------------------------------
resource "aws_vpc" "eks" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = merge(var.tags, { Name = "eks-vpc" })
}

# Enforce restricted default SG (no ingress/egress)
# Satisfies CKV2_AWS_12
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.eks.id
  # No ingress/egress blocks = deny all
  tags = merge(var.tags, { Name = "eks-default-sg" })
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = merge(var.tags, { Name = "eks-public-a" })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false
  tags = merge(var.tags, { Name = "eks-public-b" })
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.3.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = merge(var.tags, { Name = "eks-private-a" })
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.4.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false
  tags = merge(var.tags, { Name = "eks-private-b" })
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-igw" })
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "eks-nat-eip" })
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_a.id
  tags          = merge(var.tags, { Name = "eks-nat" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-public-rt" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
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

# -------------------------------
# VPC Flow Logs + IAM
# -------------------------------
resource "aws_cloudwatch_log_group" "vpc_flow_with_kms" {
  name              = "/aws/vpc/flow-logs-kms"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  tags              = merge(var.tags, { Name = "vpc-flow-logs-kms" })
}

resource "aws_iam_role" "vpc_flow" {
  name = "vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow.id


  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid    = "AllowLogWrites",
      Effect = "Allow",
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      Resource = [
        aws_cloudwatch_log_group.vpc_flow_with_kms.arn,
        "${aws_cloudwatch_log_group.vpc_flow_with_kms.arn}:*"
      ]
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.eks.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.vpc_flow_with_kms.arn
  iam_role_arn    = aws_iam_role.vpc_flow.arn
  tags            = merge(var.tags, { Name = "vpc-flow-logs" })
}

# -------------------------------
# KMS keys (with explicit policies)
# -------------------------------

# Satisfies CKV2_AWS_64 for CloudWatch Logs key
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowRootAccountFullAccess",
        Effect   = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid      = "AllowCloudWatchLogsUseOfKey",
        Effect   = "Allow",
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" },
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*",
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = aws_cloudwatch_log_group.vpc_flow_with_kms.arn
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "cw-logs-kms" })
}

# Satisfies CKV2_AWS_64 for EKS secrets encryption key
resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowRootAccountFullAccess",
        Effect   = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid      = "AllowEKSUseOfKey",
        Effect   = "Allow",
        Principal = { Service = "eks.${data.aws_region.current.name}.amazonaws.com" },
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id,
            "kms:ViaService"    = "eks.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "eks-secrets-kms" })
}

# -------------------------------
# EKS Cluster + Node Group
# -------------------------------
resource "aws_iam_role" "eks_cluster" {
  name = "eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node" {
  name = "eks-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = var.tags
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
  version  = "1.29"

  vpc_config {
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  tags = var.tags
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  scaling_config {
    desired_size = 2
    min_size     = 1
    max_size     = 3
  }

  tags = var.tags
}

# -------------------------------
# Outputs
# -------------------------------
output "cluster_name" {
  value = aws_eks_cluster.this.name
}
