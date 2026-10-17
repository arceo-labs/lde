output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "ecr_repo_url" {
  description = "ECR repository URL for the LDE image"
  value       = aws_ecr_repository.lde.repository_url
}

output "lde_service_name" {
  description = "ECS service name for LDE"
  value       = aws_ecs_service.lde.name
}

output "dtrack_api_service_name" {
  description = "ECS service name for Dependency-Track API"
  value       = aws_ecs_service.dtrack_api.name
}

output "rds_endpoint" {
  description = "Aurora PostgreSQL writer endpoint"
  value       = module.aurora_postgresql.cluster_endpoint
  sensitive   = true
}

output "secrets_arns" {
  description = "ARNs of the Secrets Manager secrets (populate values manually)"
  value = {
    github_pat     = aws_secretsmanager_secret.github_pat.arn
    dtrack_api_key = aws_secretsmanager_secret.dtrack_api_key.arn
    gemini_api_key = aws_secretsmanager_secret.gemini_api_key.arn
    basic_auth     = aws_secretsmanager_secret.basic_auth.arn
  }
}
