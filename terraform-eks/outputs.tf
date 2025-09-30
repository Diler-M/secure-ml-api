output "cluster_name"        { value = aws_eks_cluster.this.name }
output "cluster_endpoint"    { value = aws_eks_cluster.this.endpoint }
output "grafana_hint"        { value = "kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80" }