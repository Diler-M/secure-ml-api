output "cluster_name" {
  value       = aws_eks_cluster.this.name
  description = "EKS cluster name"
}

output "private_subnets" {
  value = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

output "vpc_id" {
  value = aws_vpc.eks.id
}