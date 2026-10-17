module "aurora_postgresql" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 9.0"

  name           = "${local.name_prefix}-dtrack"
  engine         = "aurora-postgresql"
  engine_version = "17.6"
  instance_class = "db.serverless"

  instances = {
    one = {}
  }

  serverlessv2_scaling_configuration = {
    min_capacity = var.db_instance_class
    max_capacity = var.db_max_acus
  }

  vpc_id                 = var.vpc_id
  create_db_subnet_group = true
  subnets                = var.private_subnet_ids

  security_group_rules = {
    dtrack_ingress = {
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.dtrack_api.id
    }
  }

  storage_encrypted         = true
  apply_immediately         = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name_prefix}-dtrack-final"

  database_name   = "dtrack"
  master_username = "dtrack"

  manage_master_user_password                            = true
  manage_master_user_password_rotation                   = true
  master_user_password_rotation_automatically_after_days = 30
}
