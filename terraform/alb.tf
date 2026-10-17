resource "aws_lb" "main" {
  name               = local.name_prefix
  internal           = var.alb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb"
    enabled = true
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-alb" })
}

# S3 bucket for ALB access logs
resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${local.name_prefix}-alb-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { "Service" : "logdelivery.elasticloadbalancing.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    }]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---- Target Groups --------------------------------------------------------

resource "aws_lb_target_group" "lde" {
  name        = "${local.name_prefix}-lde-tg"
  port        = 8002
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/api/settings"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    matcher             = "200,401" # 401 = server is up but requires auth
  }
}

resource "aws_lb_target_group" "dtrack_frontend" {
  name        = "${local.name_prefix}-dtrack-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    matcher             = "200,302"
  }
}

resource "aws_lb_target_group" "dtrack_api" {
  name        = "${local.name_prefix}-dtrack-api-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/api/version"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    matcher             = "200"
  }
}

# ---- ACM Certificate (DNS validation via Route53 if zone ID provided) ------

resource "aws_acm_certificate" "main" {
  count = var.route53_zone_id != "" ? 1 : 0

  domain_name               = var.lde_domain
  subject_alternative_names = [var.dtrack_domain]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.route53_zone_id != "" ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = coalesce(var.certificate_zone_id_override, var.route53_zone_id)
}

resource "aws_acm_certificate_validation" "main" {
  count                   = var.route53_zone_id != "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}

# ---- Listeners ------------------------------------------------------------
# Port 80 only redirects to the HTTPS listener on 443. LDE is never served
# over cleartext HTTP. The route53_zone_id validation guarantees a
# certificate, so https_listener is always true for a valid config.
resource "aws_lb_listener" "http" {
  count             = local.https_listener ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Stacks with supplied certificates and no Route 53 zone had a port-80 404
# listener. Move it so the redirect is an in-place update, not a second
# listener racing for port 80.
moved {
  from = aws_lb_listener.http_no_cert[0]
  to   = aws_lb_listener.http[0]
}

# HTTPS listener. Route 53 accounts use the certificate Terraform validates.
# With no zone, the first entry in listener_certificate_arns is the default
# certificate and any further ARNs are attached below. Terraform does not
# create or validate those certificates.
resource "aws_lb_listener" "https" {
  count             = local.https_listener ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = coalesce(
    one(aws_acm_certificate_validation.main[*].certificate_arn),
    local.issued_certificate_arn,
  )

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_certificate" "additional" {
  for_each = toset(local.additional_certificate_arns)

  listener_arn    = aws_lb_listener.https[0].arn
  certificate_arn = each.value
}

resource "aws_lb_listener_rule" "lde_https" {
  count        = local.https_listener ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lde.arn
  }

  condition {
    host_header { values = [var.lde_domain] }
  }
}

resource "aws_lb_listener_rule" "dtrack_api_https" {
  count        = local.https_listener ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 15

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dtrack_api.arn
  }

  condition {
    host_header { values = [var.dtrack_domain] }
  }
  condition {
    path_pattern { values = ["/api/*"] }
  }
}

resource "aws_lb_listener_rule" "dtrack_https" {
  count        = local.https_listener ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dtrack_frontend.arn
  }

  condition {
    host_header { values = [var.dtrack_domain] }
  }
}

# ---- Route53 A Records (optional) ----------------------------------------

resource "aws_route53_record" "lde" {
  count   = var.route53_zone_id != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.lde_domain
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "dtrack" {
  count   = var.route53_zone_id != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.dtrack_domain
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
