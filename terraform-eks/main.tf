# --- Networking ---
resource "aws_vpc" "eks" {
  cidr_block = "10.1.0.0/16"
  tags = { Name = "eks-vpc" }
}

resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.eks.id }

resource "aws_subnet" "eks_public_a" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "eks_public_b" {
  vpc_id                  = aws_vpc.eks.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.eks.id
  route { cidr_block = "0.0.0.0/0" gateway_id = aws_internet_gateway.igw.id }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.eks_public_a.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.eks_public_b.id
  route_table_id = aws_route_table.public.id
}

# --- EKS Control Plane ---
resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{Effect="Allow", Principal={Service="eks.amazonaws.com"}, Action="sts:AssumeRole"}]
  })
}
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  vpc_config { subnet_ids = [aws_subnet.eks_public_a.id, aws_subnet.eks_public_b.id] }
  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

# --- Node Group ---
resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{Effect="Allow", Principal={Service="ec2.amazonaws.com"}, Action="sts:AssumeRole"}]
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
  node_group_name = "ng-default"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [aws_subnet.eks_public_a.id, aws_subnet.eks_public_b.id]
  scaling_config { desired_size = 2, max_size = 3, min_size = 1 }
  instance_types = ["t3.medium"]
  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr_ro,
    aws_iam_role_policy_attachment.node_cni
  ]
}

# --- Helm add-ons ---
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

variable "slack_webhook_url" { type = string, default = "" }

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