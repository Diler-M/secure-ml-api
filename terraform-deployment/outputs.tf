output "ecs_cluster_name" {
  value = aws_ecs_cluster.secure_ml_cluster.name
}

output "load_balancer_dns" {
  value = aws_lb.ecs_lb.dns_name
}
