output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_version" {
  description = "EKS Kubernetes version"
  value       = aws_eks_cluster.this.version
}

output "node_group_name" {
  description = "Default node group name"
  value       = aws_eks_node_group.default.node_group_name
}

output "vpc_id" {
  description = "VPC ID used by the EKS cluster"
  value       = aws_vpc.eks.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs for worker nodes"
  value       = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}