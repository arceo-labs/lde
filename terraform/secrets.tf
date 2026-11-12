# These secrets are created as empty shells by Terraform.
# Populate actual values manually after `terraform apply`.
#
# lde/github is written by LDE itself (Settings -> GitHub auth: add orgs,
# Create app for <org>). It holds every org, its auth and its key or token
# (docs/github-app.md). lde/github-pat is the old PAT secret: LDE reads it only
# until lde/github is first written, then it can go back to REPLACE_ME.
#
# NEVER put real values in .tf files or commit them to source control.

resource "aws_secretsmanager_secret" "github" {
  name                    = "lde/github"
  description             = "GitHub org map for Library Dependency Explorer: JSON {orgs: {<org>: {auth, scan, ...}}, enterprise_app}. Holds GitHub App private keys and any PATs. Written by LDE (Settings -> GitHub auth)."
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "github" {
  secret_id     = aws_secretsmanager_secret.github.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "github_pat" {
  name                    = "lde/github-pat"
  description             = "DEPRECATED, read only to migrate into lde/github: GitHub fine-grained PATs, JSON object {org: token}. Set to REPLACE_ME once lde/github is written."
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "github_pat" {
  secret_id     = aws_secretsmanager_secret.github_pat.id
  secret_string = "REPLACE_ME"

  lifecycle {
    # Prevent Terraform from overwriting a manually-set value on subsequent applies.
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "dtrack_api_key" {
  name                    = "lde/dtrack-api-key"
  description             = "Dependency-Track API key for Library Dependency Explorer"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "dtrack_api_key" {
  secret_id     = aws_secretsmanager_secret.dtrack_api_key.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "gemini_api_key" {
  name                    = "lde/gemini-api-key"
  description             = "Google Gemini API key for package name extraction"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "gemini_api_key" {
  secret_id     = aws_secretsmanager_secret.gemini_api_key.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "basic_auth" {
  name                    = "lde/basic-auth"
  description             = "HTTP Basic Auth for LDE. JSON object {username: sha256_hex}, written by scripts/set_lde_password.py before the first plan."
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "basic_auth" {
  secret_id = aws_secretsmanager_secret.basic_auth.id
  secret_string = (
    fileexists(local.lde_basic_auth_file)
    ? file(local.lde_basic_auth_file)
    : "{\"pending\":\"pending\"}"
  )

  lifecycle {
    precondition {
      condition     = fileexists(local.lde_basic_auth_file)
      error_message = "No LDE password file at ${local.lde_basic_auth_file}. Run python3 scripts/set_lde_password.py before terraform plan. Apply does not invent a password."
    }
    ignore_changes = [secret_string]
  }
}
