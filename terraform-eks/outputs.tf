output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "Private endpoint URL for the EKS cluster"
  value       = aws_eks_cluster.this.endpoint
}

output "eks_cluster_role_arn" {
  description = "EKS cluster IAM role ARN"
  value       = aws_iam_role.eks_cluster.arn
}

output "eks_node_role_arn" {
  description = "EKS node IAM role ARN"
  value       = aws_iam_role.eks_node.arn
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.eks.id
}