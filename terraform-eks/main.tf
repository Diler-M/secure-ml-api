############################
# Networking (VPC + Subnets)
############################

resource "aws_vpc" "eks" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(var.tags, {
    Name = "eks-vpc"
  })
}

# Internet Gateway for public egress
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-igw" })
}

# Public subnets (do NOT auto-assign public IPs to satisfy CKV_AWS_130)
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.aws_region}${var.az_a_suffix}"
  map_public_ip_on_launch = false
  tags = merge(var.tags, {
    Name                        = "eks-public-a"
    "kubernetes.io/role/elb"    = "1"
  })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "${var.aws_region}${var.az_b_suffix}"
  map_public_ip_on_launch = false
  tags = merge(var.tags, {
    Name                        = "eks-public-b"
    "kubernetes.io/role/elb"    = "1"
  })
}

# Private subnets (for nodes / cluster)
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.1.101.0/24"
  availability_zone = "${var.aws_region}${var.az_a_suffix}"
  tags = merge(var.tags, {
    Name                             = "eks-private-a"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.1.102.0/24"
  availability_zone = "${var.aws_region}${var.az_b_suffix}"
  tags = merge(var.tags, {
    Name                             = "eks-private-b"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

# EIP + NAT Gateway for private subnets egress
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "eks-nat-eip" })
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_a.id
  tags          = merge(var.tags, { Name = "eks-nat" })
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.eks.id
  tags   = merge(var.tags, { Name = "eks-public-rt" })

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
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

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
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
# VPC Flow Logs (encrypted)
############################

# KMS for CloudWatch Logs
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for VPC Flow Logs (CloudWatch)"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "EnableIAMUserPermissions",
        Effect   = "Allow",
        Principal = { AWS = data.aws_caller_identity.current.account_id },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid      = "AllowCloudWatchLogsUse",
        Effect   = "Allow",
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" },
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
  tags = merge(var.tags, { Name = "kms-cloudwatch-logs" })
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flow/${aws_vpc.eks.id}"
  retention_in_days = 400                         # >= 365 (CKV_AWS_338)
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn  # Encrypt (CKV_AWS_158)
  tags              = merge(var.tags, { Name = "vpc-flow-logs" })
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

# Scope permissions to the specific Log Group (avoid Resource="*")
resource "aws_iam_role_policy" "vpc_flow" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      Resource = [
        aws_cloudwatch_log_group.vpc_flow.arn,
        "${aws_cloudwatch_log_group.vpc_flow.arn}:*"
      ]
    }]
  })
}

resource "aws_flow_log" "this" {
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow.name
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.eks.id
  tags                 = merge(var.tags, { Name = "eks-vpc-flow-logs" })
}

############################
# KMS for EKS Secrets
############################

resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS Secrets Encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # Explicit key policy (CKV2_AWS_64)
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowRootAccountAdmin",
        Effect   = "Allow",
        Principal = { AWS = data.aws_caller_identity.current.account_id },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid      = "AllowEKSToUseKey",
        Effect   = "Allow",
        Principal = { Service = "eks.amazonaws.com" },
        Action   = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
  tags = merge(var.tags, { Name = "kms-eks-secrets" })
}

############################
# EKS IAM Roles
############################

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"
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
  name = "${var.cluster_name}-node-role"
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

############################
# EKS Cluster (private endpoint, logging, secrets enc)
############################

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  kubernetes_network_config {
    ip_family = "ipv4"
  }

  # Control plane logging enabled (CKV_AWS_37)
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Secrets encryption (CKV_AWS_58)
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]

  tags = var.tags
}

############################
# EKS Node Group (private subnets)
############################

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_role_arn   = aws_iam_role.eks_node.arn
  node_group_name = "${var.cluster_name}-ng"
  subnet_ids      = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  capacity_type   = "ON_DEMAND"
  instance_types  = var.node_instance_types

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  tags = var.tags

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr_ro,
    aws_iam_role_policy_attachment.node_cni
  ]
}