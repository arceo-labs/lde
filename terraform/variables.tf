variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "env" {
  description = "Environment name (e.g. prod, staging)"
  type        = string
  default     = "prod"
}

variable "lde_domain" {
  description = "Hostname for the Library Dependency Explorer UI"
  type        = string
  default     = "lde.internal"
}

variable "dtrack_domain" {
  description = "Hostname for the Dependency-Track UI"
  type        = string
  default     = "dtrack.internal"
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID for A records and ACM DNS validation if certificate_zone_id_override isn't set. Leave empty only when listener_certificate_arns names certificates that already exist."
  type        = string
  default     = ""

  validation {
    condition     = var.route53_zone_id != "" || length(var.listener_certificate_arns) > 0
    error_message = "Set route53_zone_id, or pass listener_certificate_arns for certificates that already exist. An empty zone creates a port-80 404 listener and does not attach the target groups."
  }

  validation {
    condition     = var.route53_zone_id == "" || length(var.listener_certificate_arns) == 0
    error_message = "Pass listener_certificate_arns only when route53_zone_id is empty. With a zone, Terraform requests the certificate."
  }
}

variable "certificate_zone_id_override" {
  default     = ""
  description = "Route53 hosted zone ID to use for ACM DNS validation if it needs to differ from route53_zone_id; for instance if that zone is private"
  type        = string
  validation {
    condition     = var.route53_zone_id != "" || var.certificate_zone_id_override == ""
    error_message = "If route53_zone_id is not provided then you can't provide certificate_zone_id_override either"
  }
}

variable "lde_image" {
  description = "ECR image URI for LDE (e.g. <account-id>.dkr.ecr.<region>.amazonaws.com/lde:latest). Leave empty to use the repository created by this stack, tagged :latest."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Networking. This stack deploys into an existing VPC that you supply. Provide
# the VPC, subnets, and ECS cluster below (previously sourced from a shared
# remote state in the original private deployment).
# ---------------------------------------------------------------------------

variable "vpc_id" {
  description = "ID of the VPC to deploy into"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the ALB and public-facing ECS tasks"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the database and internal mounts"
  type        = list(string)
}

variable "ecs_cluster_name" {
  description = "Name of an existing ECS cluster to run services in. Plan fails if this cluster does not exist."
  type        = string
}

variable "lde_basic_auth_file" {
  description = "JSON file {username: sha256_hex} written by scripts/set_lde_password.py. Empty uses ~/.lde/basic-auth.json. Plan fails when the file is missing."
  type        = string
  default     = ""
}

variable "listener_certificate_arns" {
  description = "Existing ACM certificate ARNs to serve when route53_zone_id is empty. The first ARN is the listener default. Terraform does not create or validate these certificates."
  type        = list(string)
  default     = []
}

variable "alb_internal" {
  description = "When true, the load balancer has only private addresses. Set false to give it public addresses. alb_ingress_cidr_blocks is then matched against the client public address."
  type        = bool
  default     = true
}

variable "alb_ingress_cidr_blocks" {
  description = "CIDR blocks allowed to reach the ALB on 80/443. Use VPN or office ranges when alb_internal is true, or the client public address as a /32 when it is false."
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "alb_ingress_security_group_ids" {
  description = "Optional security group IDs allowed to reach the ALB on 443 (e.g. an automation runner in the same VPC)."
  type        = list(string)
  default     = []
}

variable "dtrack_api_image" {
  description = "Dependency-Track API server Docker image"
  type        = string
  default     = "dependencytrack/apiserver:4.14.5" # pinned: a task restart must not upgrade it
}

variable "dtrack_frontend_image" {
  description = "Dependency-Track frontend Docker image"
  type        = string
  default     = "dependencytrack/frontend:4.14.5" # pinned: a task restart must not upgrade it
}

variable "db_instance_class" {
  description = "Aurora Serverless v2 minimum ACU (0.5 = ~1 GB RAM, suitable for dev/staging). Billed per ACU-hour; Dependency-Track keeps connections open, so Aurora never pauses below this."
  type        = number
  default     = 0.5
}

variable "db_max_acus" {
  description = "Aurora Serverless v2 maximum ACU"
  type        = number
  default     = 4
}
