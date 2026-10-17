resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "ALB: inbound 80 and 443 from internet"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP from allowed clients"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidr_blocks
  }
  ingress {
    description = "HTTPS from allowed clients"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidr_blocks
  }
  # Optional: allow other services in your VPC (referenced by security group)
  # to reach the ALB on 443 — e.g. an automation runner calling the LDE API.
  dynamic "ingress" {
    for_each = length(var.alb_ingress_security_group_ids) > 0 ? [1] : []
    content {
      description     = "HTTPS from allowed security groups"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      security_groups = var.alb_ingress_security_group_ids
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-sg-alb" })
}

resource "aws_security_group" "lde" {
  name        = "${local.name_prefix}-lde"
  description = "LDE container: inbound from ALB on 8002, outbound HTTPS"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8002
    to_port         = 8002
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-sg-lde" })
}

# DTrack API — accepts traffic from ALB (/api/* rules) and from LDE (server-side calls).
resource "aws_security_group" "dtrack_api" {
  name        = "${local.name_prefix}-dtrack-api"
  description = "DT API: inbound 8080 from ALB and LDE only"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id, aws_security_group.lde.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-sg-dtrack-api" })
}

# DTrack Frontend — accepts traffic from ALB only; LDE never calls the frontend.
resource "aws_security_group" "dtrack_frontend" {
  name        = "${local.name_prefix}-dtrack-frontend"
  description = "DT Frontend: inbound 8080 from ALB only"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-sg-dtrack-frontend" })
}
