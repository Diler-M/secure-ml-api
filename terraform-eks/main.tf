terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  cluster_name = var.cluster_name
  tags = merge(var.tags, { Project = "secure-ml-api" })
}

# ---------------- VPC & Subnets ----------------
resource "aws_vpc" "eks" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(var.tags, { Name = "eks-vpc" })
}

# RESTRICT DEFAULT SECURITY GROUP (Checkov CKV2_AWS_12)
resource "aws_default_security_group" "default" {
  vpc_id                 = aws_vpc.eks.id
  # Explicitly remove all rules
  ingress = []
  egress  = []
  tags    = merge(var.tags, { Name = "default-sg-restricted" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-igw" })
}

# Public subnets (no auto public IP on nodes; used for ALB)
resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.1.1.0/24"
  availability_zone = "${var.aws_region}${var.az_a_suffix}"
  map_public_ip_on_launch = false
  tags = {
    Name                     = "eks-public-a"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.1.2.0/24"
  availability_zone = "${var.aws_region}${var.az_b_suffix}"
  map_public_ip_on_launch = false
  tags = {
    Name                     = "eks-public-b"
    "kubernetes.io/role/elb" = "1"
  }
}

# Private subnets (nodes live here)
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.1.3.0/24"
  availability_zone = "${var.aws_region}${var.az_a_suffix}"
  map_public_ip_on_launch = false
  tags = {
    Name                              = "eks-private-a"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.1.4.0/24"
  availability_zone = "${var.aws_region}${var.az_b_suffix}"
  map_public_ip_on_launch = false
  tags = {
    Name                              = "eks-private-b"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# NAT for private egress
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
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = merge(var.tags, { Name = "eks-public-rt" })
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
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = merge(var.tags, { Name = "eks-private-rt" })
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# ---------------- VPC Flow Logs (with KMS) ----------------
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = merge(var.tags, { Name = "cw-logs-kms" })
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flow/${aws_vpc.eks.id}"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  tags              = merge(var.tags, { Name = "vpc-flow-logs" })
}

resource "aws_iam_role" "vpc_flow" {
  name = "${local.cluster_name}-vpc-flow-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        Resource = aws_cloudwatch_log_group.vpc_flow.arn
      }
    ]
  })
}

resource "aws_flow_log" "vpc" {
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow.name
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.eks.id
  tags                 = merge(var.tags, { Name = "vpc-flow-log" })
}

# ---------------- EKS: Secrets KMS ----------------
resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS Secrets Encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { AWS = "*" },
      Action   = [
        "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*",
        "kms:List*", "kms:ReEncrypt*"
      ],
      Resource = "*",
      Condition = {
        StringEquals = {
          "kms:ViaService" = "eks.${var.aws_region}.amazonaws.com"
        }
      }
    }]
  })
  tags = merge(var.tags, { Name = "eks-secrets-kms" })
}

# ---------------- EKS Cluster & Node Group ----------------
resource "aws_iam_role" "eks_cluster" {
  name = "${local.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = local.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "scheduler", "controllerManager"]

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
  tags       = local.tags
}

resource "aws_iam_role" "eks_node" {
  name = "${local.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = local.tags
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

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.cluster_name}-ng"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 4
  }

  instance_types = ["t3.medium"]
  ami_type       = "AL2_x86_64"

  tags = local.tags

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr_ro,
    aws_iam_role_policy_attachment.node_cni
  ]
}

output "cluster_name" {
  value = aws_eks_cluster.this.name
}

# Discover current account and region for the KMS policy principals/conditions
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Explicit policy for the CloudWatch Logs KMS key (required by CKV2_AWS_64)
resource "aws_kms_key_policy" "cloudwatch_logs" {
  key_id = aws_kms_key.cloudwatch_logs.key_id

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "cw-logs-kms-policy"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUseOfTheKey"
        Effect    = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource  = "*"
        Condition = {
          ArnEquals = {
            # Limit usage to your specific log group
            "kms:EncryptionContext:aws:logs:arn" = aws_cloudwatch_log_group.vpc_flow.arn
          }
        }
      }
    ]
  })
}
