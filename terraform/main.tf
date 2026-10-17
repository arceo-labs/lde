
locals {
  name_prefix = "${var.env}-lde"
  common_tags = {
    Project     = "library-dependency-explorer"
    Environment = var.env
    ManagedBy   = "terraform"
  }
  # Route 53 accounts get a Terraform-requested certificate. Everyone else
  # passes ARNs that already exist. An empty list and an empty zone means
  # there is no HTTPS listener, and variable validation rejects that plan.
  https_listener         = var.route53_zone_id != "" || length(var.listener_certificate_arns) > 0
  issued_certificate_arn = length(var.listener_certificate_arns) > 0 ? var.listener_certificate_arns[0] : ""
  additional_certificate_arns = (
    var.route53_zone_id == "" && length(var.listener_certificate_arns) > 1
    ? slice(var.listener_certificate_arns, 1, length(var.listener_certificate_arns))
    : []
  )
  # First apply reads this file. Later applies ignore the secret value.
  lde_basic_auth_file = (
    var.lde_basic_auth_file != ""
    ? var.lde_basic_auth_file
    : pathexpand("~/.lde/basic-auth.json")
  )
}
