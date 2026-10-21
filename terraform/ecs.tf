data "aws_ecs_cluster" "existing" {
  cluster_name = var.ecs_cluster_name
}

resource "aws_cloudwatch_log_group" "lde" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "dtrack_api" {
  name              = "/ecs/${local.name_prefix}-dtrack-api"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "dtrack_frontend" {
  name              = "/ecs/${local.name_prefix}-dtrack-frontend"
  retention_in_days = 14
}

# ---- LDE Task Definition --------------------------------------------------

# Sized from measured use (2026-10): ~5% of 0.5 vCPU and ~100 MB.
# See docs/aws-cost-control.md.
resource "aws_ecs_task_definition" "lde" {
  family                   = local.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.lde_task.arn

  volume {
    name = "lde-data"
    efs_volume_configuration {
      file_system_id     = module.efs.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = module.efs.access_points["lde"].id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([{
    name      = "lde"
    image     = var.lde_image != "" ? var.lde_image : "${aws_ecr_repository.lde.repository_url}:latest"
    essential = true

    portMappings = [{
      containerPort = 8002
      hostPort      = 8002
      protocol      = "tcp"
    }]

    environment = [
      { name = "PORT", value = "8002" },
      { name = "LDE_DATA_DIR", value = "/app/data" },
      { name = "LDE_SECRETS_SOURCE", value = "aws" },
      { name = "LDE_DISABLE_ORT", value = "1" },
      { name = "LDE_ALLOWED_ORIGIN", value = "https://${var.lde_domain}" },
      { name = "LDE_DTRACK_URL", value = "http://${local.name_prefix}-dtrack-api.${local.name_prefix}.local:8080" },
      { name = "LDE_DTRACK_UI_URL", value = "https://${var.dtrack_domain}" },
      { name = "AWS_DEFAULT_REGION", value = var.aws_region },
    ]

    # No `secrets` block: the app reads Secrets Manager itself (secrets_loader.py,
    # via the task role). Injecting a secret here would copy every org's PAT into
    # the task environment.

    mountPoints = [{
      containerPath = "/app/data"
      sourceVolume  = "lde-data"
      readOnly      = false
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.lde.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "lde"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('localhost',8002)); s.close()\""]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 15
    }
  }])
}

resource "aws_ecs_service" "lde" {
  name                               = local.name_prefix
  cluster                            = data.aws_ecs_cluster.existing.cluster_name
  task_definition                    = aws_ecs_task_definition.lde.arn
  desired_count                      = 1
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  health_check_grace_period_seconds  = 30
  enable_execute_command             = true
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  wait_for_steady_state              = true

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.lde.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.lde.arn
    container_name   = "lde"
    container_port   = 8002
  }

  depends_on = [
    aws_lb_listener_rule.lde_https,
    aws_iam_role_policy_attachment.ecs_execution_managed,
    module.efs,
  ]

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# ---- Dependency-Track API Task Definition ---------------------------------

# Sized from measured use (2026-10, on 1 vCPU): 0.26 vCPU average and 0.34
# p90 during the full NVD mirror, ~600 MB peak. Memory stays at 2 GB for JVM
# heap headroom. See docs/aws-cost-control.md.
resource "aws_ecs_task_definition" "dtrack_api" {
  family                   = "${local.name_prefix}-dtrack-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.dtrack_execution.arn
  task_role_arn            = aws_iam_role.dtrack_task.arn

  container_definitions = jsonencode([{
    name      = "dtrack-api"
    image     = var.dtrack_api_image
    essential = true

    portMappings = [{
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
    }]

    environment = [
      { name = "ALPINE_DATABASE_MODE", value = "external" },
      { name = "ALPINE_DATABASE_DRIVER", value = "org.postgresql.Driver" },
      { name = "ALPINE_DATABASE_DRIVER_PATH", value = "/opt/owasp/lib/postgresql.jar" },
      { name = "ALPINE_DATABASE_URL",
      value = "jdbc:postgresql://${module.aurora_postgresql.cluster_endpoint}:5432/dtrack" },
      { name = "ALPINE_DATABASE_USERNAME", value = "dtrack" },
    ]
    # Task scheduler cadences and vulnerability source and analyzer flags are database settings
    # that Dependency-Track does not read from the environment.
    # scripts/bootstrap_dtrack.py applies them (COST_SETTINGS).

    secrets = [
      {
        name      = "ALPINE_DATABASE_PASSWORD"
        valueFrom = "${module.aurora_postgresql.cluster_master_user_secret[0].secret_arn}:password::"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.dtrack_api.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "dtrack-api"
      }
    }

    # DT API server takes ~40s to initialize on cold start at 1 vCPU
    healthCheck = {
      command     = ["CMD-SHELL", "curl -sf http://localhost:8080/api/version || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 5
      startPeriod = 60
    }
  }])
}

resource "aws_ecs_service" "dtrack_api" {
  name                               = "${local.name_prefix}-dtrack-api"
  cluster                            = data.aws_ecs_cluster.existing.cluster_name
  task_definition                    = aws_ecs_task_definition.dtrack_api.arn
  desired_count                      = 1
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  health_check_grace_period_seconds  = 180 # slower JVM start at 0.5 vCPU
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  wait_for_steady_state              = true

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.dtrack_api.id]
    assign_public_ip = true
  }

  # DT API: Cloud Map for LDE server-side calls + ALB for browser /api/* requests.
  # awsvpc mode: port must not be specified in service_registries for A-record namespaces.
  service_registries {
    registry_arn = aws_service_discovery_service.dtrack_api.arn
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.dtrack_api.arn
    container_name   = "dtrack-api"
    container_port   = 8080
  }

  depends_on = [
    module.aurora_postgresql,
    aws_iam_role_policy_attachment.ecs_execution_managed,
    aws_lb_listener_rule.dtrack_api_https,
  ]

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# ---- Dependency-Track Frontend Task Definition ----------------------------

resource "aws_ecs_task_definition" "dtrack_frontend" {
  family                   = "${local.name_prefix}-dtrack-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.dtrack_execution.arn
  task_role_arn            = aws_iam_role.dtrack_task.arn

  container_definitions = jsonencode([{
    name      = "dtrack-frontend"
    image     = var.dtrack_frontend_image
    essential = true

    portMappings = [{
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
    }]

    environment = [
      {
        name  = "API_BASE_URL"
        value = "https://${var.dtrack_domain}"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.dtrack_frontend.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "dtrack-frontend"
      }
    }
  }])
}

resource "aws_ecs_service" "dtrack_frontend" {
  name             = "${local.name_prefix}-dtrack-frontend"
  cluster          = data.aws_ecs_cluster.existing.cluster_name
  task_definition  = aws_ecs_task_definition.dtrack_frontend.arn
  desired_count    = 1
  launch_type      = "FARGATE"
  platform_version = "LATEST"

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.dtrack_frontend.id]
    assign_public_ip = true
  }

  # Attach when the HTTPS listener exists. That is a Route 53 zone or
  # listener_certificate_arns. Without either, variable validation fails plan.
  dynamic "load_balancer" {
    for_each = local.https_listener ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.dtrack_frontend.arn
      container_name   = "dtrack-frontend"
      container_port   = 8080
    }
  }

  depends_on = [
    aws_lb_listener.https,
    aws_ecs_service.dtrack_api,
  ]

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# ---- Cloud Map for DT API internal service discovery ----------------------

resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "${local.name_prefix}.local"
  vpc         = var.vpc_id
  description = "Internal service discovery for ${local.name_prefix}"
}

resource "aws_service_discovery_service" "dtrack_api" {
  name = "${local.name_prefix}-dtrack-api"

  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.main.id
    routing_policy = "MULTIVALUE"

    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}
