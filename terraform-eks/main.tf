############################################################
# Networking (VPC, Subnets, Routes, NAT)
############################################################

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

resource "aws_vpc" "eks" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "eks-vpc" })
}

# Lock down default SG to satisfy CKV2_AWS_12
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.eks.id

  # No ingress/egress rules means all traffic is denied by default
  tags = merge(var.tags, { Name = "eks-default-sg-locked" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-igw" })
}

# Public subnets
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = local.azs[0]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "public-a" })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = local.azs[length(local.azs) > 1 ? 1 : 0]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "public-b" })
}

# Private subnets
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10)
  availability_zone = local.azs[0]
  tags              = merge(var.tags, { Name = "private-a" })
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 11)
  availability_zone = local.azs[length(local.azs) > 1 ? 1 : 0]
  tags              = merge(var.tags, { Name = "private-b" })
}

# EIP and NAT for private subnets
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "eks-nat-eip" })
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_a.id
  tags          = merge(var.tags, { Name = "eks-nat" })
  depends_on    = [aws_internet_gateway.igw]
}

# Route tables
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
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public_a.id
}

resource "aws_route_table_association" "public_b" {
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public_b.id
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
  route_table_id = aws_route_table.private.id
  subnet_id      = aws_subnet.private_a.id
}

resource "aws_route_table_association" "private_b" {
  route_table_id = aws_route_table.private.id
  subnet_id      = aws_subnet.private_b.id
}

############################################################
# KMS for EKS Secrets (policy tightened for Checkov)
############################################################

data "aws_iam_policy_document" "kms_eks_secrets" {
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

  # Allow EKS control plane with constraints
  statement {
    sid    = "AllowEKSUseOfKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["eks.${data.aws_region.current.name}.amazonaws.com"]
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
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_eks_secrets.json
  tags                    = merge(var.tags, { Name = "eks-secrets-kms" })
}

############################################################
# IAM for EKS
############################################################

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { Name = "${var.cluster_name}-cluster-role" })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { Name = "${var.cluster_name}-node-role" })
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

############################################################
# EKS Cluster & Node Group
############################################################

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.29"

  vpc_config {
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  kubernetes_network_config {
    ip_family = "ipv4"
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  tags = merge(var.tags, { Name = var.cluster_name })

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-ng"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  disk_size       = 20
  capacity_type   = "ON_DEMAND"
  instance_types  = ["t3.medium"]

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-ng" })

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr_ro,
    aws_iam_role_policy_attachment.node_cni
  ]
}