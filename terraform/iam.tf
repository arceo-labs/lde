data "aws_iam_policy_document" "ecs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ---- Task Execution Role (used by ECS agent to pull image + inject secrets) ----

resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_secrets" {
  statement {
    sid     = "ReadLDESecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.github_pat.arn,
      aws_secretsmanager_secret.dtrack_api_key.arn,
      aws_secretsmanager_secret.gemini_api_key.arn,
      aws_secretsmanager_secret.basic_auth.arn,
    ]
  }
  statement {
    sid       = "ReadECRToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name   = "read-lde-secrets"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_secrets.json
}

# ---- Task Role (used by the running LDE container to call Secrets Manager) ----
# The secrets_loader.py uses ECS task credentials to call Secrets Manager at
# runtime.  The execution role covers startup injection; this role covers
# runtime re-reads (e.g. when secrets rotate).

resource "aws_iam_role" "lde_task" {
  name               = "${local.name_prefix}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

data "aws_iam_policy_document" "lde_task_secrets" {
  statement {
    sid     = "ReadLDESecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.github_pat.arn,
      aws_secretsmanager_secret.dtrack_api_key.arn,
      aws_secretsmanager_secret.gemini_api_key.arn,
      aws_secretsmanager_secret.basic_auth.arn,
    ]
  }
}

resource "aws_iam_role_policy" "lde_task_secrets" {
  name   = "read-lde-secrets"
  role   = aws_iam_role.lde_task.id
  policy = data.aws_iam_policy_document.lde_task_secrets.json
}

# ---- DTrack Execution Role (scoped to db_password only) ---------------------
# Separate from the LDE execution role so DTrack tasks cannot read LDE secrets
# (github_pat, gemini_api_key, dtrack_api_key, basic_auth) at startup.

resource "aws_iam_role" "dtrack_execution" {
  name               = "${local.name_prefix}-dtrack-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

resource "aws_iam_role_policy_attachment" "dtrack_execution_managed" {
  role       = aws_iam_role.dtrack_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "dtrack_execution_secrets" {
  statement {
    sid     = "ReadDTrackDbPassword"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      module.aurora_postgresql.cluster_master_user_secret[0].secret_arn,
    ]
  }
  statement {
    sid       = "ReadECRToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "dtrack_execution_secrets" {
  name   = "read-dtrack-secrets"
  role   = aws_iam_role.dtrack_execution.id
  policy = data.aws_iam_policy_document.dtrack_execution_secrets.json
}

# ---- DT Task Role (minimal — DT doesn't need Secrets Manager at runtime) ----

resource "aws_iam_role" "dtrack_task" {
  name               = "${local.name_prefix}-dtrack-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}
