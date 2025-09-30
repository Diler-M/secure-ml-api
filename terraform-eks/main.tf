########################################
# Networking (2x public + 2x private)
########################################
resource "aws_vpc" "eks" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "eks-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks.id
  tags = { Name = "eks-igw" }
}

# Public subnets (no instances here; only for NAT/Ingress)
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.aws_region}${var.az_a_suffix}"
  map_public_ip_on_launch = true
  tags = { Name = "eks-public-a", "kubernetes.io/role/elb" = "1" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "${var.aws_region}${var.az_b_suffix}"
  map_public_ip_on_launch = true
  tags = { Name = "eks-public-b", "kubernetes.io/role/elb" = "1" }
}

# Private subnets for worker nodes (NO public IPs)
resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.101.0/24"
  availability_zone       = "${var.aws_region}${var.az_a_suffix}"
  map_public_ip_on_launch = false
  tags = { Name = "eks-private-a", "kubernetes.io/role/internal-elb" = "1" }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.102.0/24"
  availability_zone       = "${var.aws_region}${var.az_b_suffix}"
  map_public_ip_on_launch = false
  tags = { Name = "eks-private-b", "kubernetes.io/role/internal-elb" = "1" }
}

# Public route table → IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.eks.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "eks-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# NAT for private egress
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags = { Name = "eks-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_a.id
  tags = { Name = "eks-nat" }
  depends_on = [aws_internet_gateway.igw]
}

# Private route table → NAT
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.eks.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "eks-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}
resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

########################################
# Lock down Default SG (no rules)
########################################
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.eks.id
  revoke_rules_on_delete = true

  # Explicitly no ingress/egress (most secure; pods/services get their own SGs)
  ingress = []
  egress  = []

  tags = { Name = "eks-default-sg-locked" }
}

########################################
# VPC Flow Logs → CloudWatch
########################################
resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flow/${aws_vpc.eks.id}"
  retention_in_days = 14
}

resource "aws_iam_role" "vpc_flow" {
  name = "vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service="vpc-flow-logs.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Action=[
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      Resource="*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  log_destination      = aws_cloudwatch_log_group.vpc_flow.arn
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.eks.id
  log_destination_type = "cloud-watch-logs"
}

########################################
# EKS — cluster + nodes (private)
########################################
# KMS for secrets encryption
resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS Secrets Encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# Cluster role
resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service="eks.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    endpoint_private_access = true
    endpoint_public_access  = false
    # (No public CIDRs because public access is disabled)
  }

  # Control plane logging — enable all
  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  # Secrets encryption
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

# Node role
resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service="ec2.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
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
  node_group_name = "ng-private"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr_ro,
    aws_iam_role_policy_attachment.node_cni
  ]
}

########################################
# Helm add-ons (unchanged)
########################################
resource "helm_release" "ingress_nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  version          = "4.11.1"
  namespace        = "nginx-ingress"
  create_namespace = true
}

resource "helm_release" "kps" {
  name             = "kube-prometheus-stack"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  version          = "61.7.0"
  namespace        = "monitoring"
  create_namespace = true
}

resource "helm_release" "falco" {
  name             = "falco"
  repository       = "https://falcosecurity.github.io/charts"
  chart            = "falco"
  version          = "4.2.5"
  namespace        = "falco"
  create_namespace = true
  values = [yamlencode({
    falcosidekick = {
      enabled = true
      config = {
        slack = {
          webhookurl      = var.slack_webhook_url
          minimumpriority = "warning"
        }
      }
    }
  })]
}

resource "helm_release" "argo_rollouts" {
  name             = "argo-rollouts"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-rollouts"
  version          = "2.38.6"
  namespace        = "argo-rollouts"
  create_namespace = true
}
