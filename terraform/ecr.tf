# ECR repository for the LDE container image.
#
# This is a self-contained repository. If your organization shares images
# across accounts, attach a repository policy granting the relevant principals
# pull access (see repository_policy_principals in the AWS provider docs).
resource "aws_ecr_repository" "lde" {
  name                 = local.name_prefix
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags
}
