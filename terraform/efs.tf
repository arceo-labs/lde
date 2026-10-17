module "efs" {
  source  = "terraform-aws-modules/efs/aws"
  version = "2.2.0"

  access_points = {
    lde = {
      name = "lde"
      posix_user = {
        gid = 1000
        uid = 1000
      }
      root_directory = {
        creation_info = {
          owner_gid   = 1000
          owner_uid   = 1000
          permissions = "755"
        }
        path = "/lde"
      }
    }
  }
  create_backup_policy = true
  enable_backup_policy = true
  encrypted            = true
  # lifecycle_policy = {
  #   transition_to_ia = "AFTER_30_DAYS"
  # }
  mount_targets = {
    for v in var.private_subnet_ids : v => { subnet_id = v }
  }
  name                  = "${local.name_prefix}-efs"
  security_group_name   = "${local.name_prefix}-efs"
  security_group_vpc_id = var.vpc_id
  security_group_ingress_rules = {
    lde = {
      description                  = "NFS ingress from lde application security group"
      referenced_security_group_id = aws_security_group.lde.id
    },
  }
}
