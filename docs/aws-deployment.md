# AWS ECS Deployment Guide — Library Dependency Explorer

This guide covers deploying LDE and Dependency-Track to AWS ECS Fargate using
Terraform. The stack deploys into an existing VPC and ECS cluster that you supply
(see `terraform/terraform.tfvars.example`).

---

## Architecture overview

```
Allowed clients (VPN / office CIDRs, or a peered SG)
  │
  ▼
Application Load Balancer (internal)   ← ACM TLS certificate
  │ lde.example.com               │ dtrack.example.com
  ▼                                     ▼
LDE (ECS Fargate)               DT Frontend (ECS Fargate)
  │ port 8002                           │ port 8080
  │ EFS mount → /app/data               │
  │ Secrets Manager overlay             ▼
  │                               DT API Server (ECS Fargate)
  │ → api.github.com                    │ port 8080 (Cloud Map)
  │ → generativelanguage.googleapis.com │
  └────────────────────────────────────►│
                                        ▼
                                 Aurora PostgreSQL (RDS Serverless v2)
```

All resources run in an existing VPC that you provide via `vpc_id`, `public_subnet_ids`,
and `private_subnet_ids`. `alb_internal` defaults to true. The ALB is internal unless
`alb_internal` is false. Inbound access is restricted to the CIDR ranges in
`alb_ingress_cidr_blocks` (and, optionally, the security groups in
`alb_ingress_security_group_ids`). With `alb_internal = false` the load balancer has
public addresses; set the allowlist to the client public IPv4 address as a `/32`.
Changing `alb_internal` on an existing load balancer replaces it.
Turn deletion protection off before that apply, then turn it back on. Services run in
the ECS cluster named by `ecs_cluster_name`.

---

## Prerequisites

### Tools

```bash
brew install awscli
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
terraform version   # terraform/terraform.tf requires >= 1.15
```

### AWS credentials

Set the profile for the session — all subsequent `aws` and `terraform` commands pick it up:

```bash
export AWS_PROFILE=your-profile
aws sts get-caller-identity   # verify access to <AWS_ACCOUNT_ID>
```

### One-time Terraform state bootstrap

Run once per account before the first `terraform apply`. The S3 bucket must exist before
`terraform init` can use it as the backend. No DynamoDB table is needed — state locking
uses S3 native conditional writes (`use_lockfile = true`).

```bash
aws s3 mb s3://REPLACE_ME-terraform-state --region us-east-1
aws s3api put-bucket-versioning \
  --bucket REPLACE_ME-terraform-state \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --bucket REPLACE_ME-terraform-state \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

Point Terraform at the bucket. `terraform/terraform.tf` names a placeholder bucket;
`backend.hcl` overrides it and stays out of git.

```bash
cat > terraform/backend.hcl <<'EOF'
bucket       = "REPLACE_ME-terraform-state"
key          = "library-dependency-explorer/terraform.tfstate"
region       = "us-east-1"
encrypt      = true
use_lockfile = true
EOF
```

---

## Step 1 — Test code changes locally

Before touching AWS, confirm the PAT-based GitHub client and Basic Auth work
on your machine.

### 1a. Test GitHub PAT auth

1. Generate a GitHub fine-grained PAT from your machine account:
   - Settings → Developer settings → Personal access tokens → Fine-grained tokens
   - Resource owner: the organization that owns the repositories, not your user
   - Repository access: All repositories
   - Repository permissions:
     - `Contents: Read-only` — required for fetching files, listing trees, **and** the dependency graph SBOM endpoint (`GET /repos/.../dependency-graph/sbom` is gated by Contents, not a separate permission)
     - `Metadata: Read-only` — required for listing org repos; always mandatory and auto-included in all fine-grained PATs

2. Start the server and paste the PAT in Settings:

```bash
cd library-dependency-explorer
python3 server.py
# Open http://localhost:8002 → Settings → paste PAT → Save
```

3. Verify the Settings page shows "authenticated" with your GitHub username.

4. Trigger a test ingest (Ingest Dependencies → enter one repo → Start run).
   Confirm the run completes and DT shows the new project. Ingest always uses
   `github_sbom`.

### 1b. Test Basic Auth locally

Generate a password hash:

```bash
python3 -c "import hashlib, json; print(json.dumps({'admin': hashlib.sha256(b'yourpassword').hexdigest()}))"
```

Set it in `.settings.json` (do NOT commit this):

```json
{
  "basic_auth_credentials": "{\"admin\": \"<sha256_hex>\"}"
}
```

Restart the server and confirm:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8002/  # → 401
curl -u admin:yourpassword http://localhost:8002/api/settings    # → 200
```

---

## Step 2 — Build and push to ECR

```bash
cd library-dependency-explorer

# Step 1: Initialise Terraform and apply only the ECR repository to get the repo URL
cd terraform
cp terraform.tfvars.example terraform.tfvars   # edit with your values
terraform init -backend-config=backend.hcl
terraform apply -target=aws_ecr_repository.lde

ECR_URL=$(terraform output -raw ecr_repo_url)

# Step 2: Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin "$ECR_URL"

# Step 3: Build and push
# --platform linux/amd64 is required when building on Apple Silicon for Fargate x86 tasks.
# Build from an export of HEAD so the image matches $GIT_SHA: untracked files
# in the working tree never reach it. Build the extracted directory, not a tar
# on stdin: Docker skips .dockerignore for a stdin tar.
cd ..
GIT_SHA=$(git rev-parse --short HEAD)
BUILD_DIR=$(mktemp -d)
git archive HEAD | tar -x -C "$BUILD_DIR"
docker build --platform linux/amd64 -t lde:latest "$BUILD_DIR"
docker tag lde:latest "$ECR_URL:$GIT_SHA"
docker push "$ECR_URL:$GIT_SHA"
```

Update `terraform.tfvars`:

```hcl
lde_image = "<AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/dev-lde:<git-sha>"
```

---

## Step 3 — Provision infrastructure

This module does not create a cluster, a VPC, or subnets. Confirm the cluster
before `terraform plan`. `MISSING` and `INACTIVE` both mean it is not usable.
A deleted cluster stays `INACTIVE` and still occupies the name, so delete that
name before creating it again.

```bash
export ECS_CLUSTER=your-ecs-cluster
aws ecs describe-clusters --clusters "$ECS_CLUSTER" \
  --query 'clusters[0].status' --output text
```

Stop unless the output is `ACTIVE`. Otherwise:

```bash
aws ecs delete-cluster --cluster "$ECS_CLUSTER"   # only when the status was INACTIVE
aws ecs create-cluster --cluster-name "$ECS_CLUSTER"
aws ecs describe-clusters --clusters "$ECS_CLUSTER" \
  --query 'clusters[0].status' --output text       # must print ACTIVE
```

`private_subnet_ids` is required. Use private subnets when the VPC has them.
When it does not, set `private_subnet_ids` to the same IDs as `public_subnet_ids`.
The tasks set `assign_public_ip = true`, so that configuration has a route to
the internet. Do not invent a NAT for this case.

Set the LDE password before `terraform plan`. The script asks for a username and password, writes `~/.lde/basic-auth.json` (mode 0600), and writes the plaintext to `~/.lde/lde-admin.txt`. The browser username is the one you typed. The browser password is the plaintext. Dependency-Track's first visit is username `admin`, password `admin`. Plan fails when the JSON file is missing.

```bash
python3 scripts/set_lde_password.py
python3 scripts/check_aws.py preflight   # read-only; fix every FAIL line first
cd terraform
terraform plan   # review what will be created. Read the plan's add count.
terraform apply  # creates ECS services, ALB, EFS, RDS, Secrets Manager shells, IAM
```

No new VPC is provisioned. The apply takes approximately 15–20 minutes (RDS Aurora
cluster creation is the longest step). Leave `route53_zone_id` empty only when
`listener_certificate_arns` lists certificates that already exist. Terraform does
not create or validate those certificates. An empty zone with an empty certificate
list fails `terraform plan`. Passing both a zone and that list also fails plan.

Approximate monthly cost in `us-east-1` with the example sizes, before traffic. These figures are measured from a running stack; see [AWS cost control](aws-cost-control.md) for the breakdown and further savings:

| Resource | Size | Approx. USD / month |
|---|---|---|
| Fargate: LDE, DT API, DT frontend | 0.25 + 0.5 + 0.25 vCPU, 0.5 + 2 + 0.5 GB, one task each | 39 |
| Aurora PostgreSQL Serverless v2 | 0.5 ACU minimum (`db_instance_class`), ~0.52 average | 55 |
| Application Load Balancer | one ALB, low LCU usage | 17 |
| Public IPv4 addresses | 5: two for the ALB, one per task | 18 |
| Secrets Manager (5 secrets), Route 53, EFS, CloudWatch Logs, ECR | small | 4 |
| **Total** | | **~133** |

The Aurora figure assumes Step 5 has run `bootstrap_dtrack.py`, which applies Dependency-Track's cost settings. Without them, Aurora costs about $45 a month more. The stack bills until Teardown. Aurora, the ALB and the public addresses bill while idle.

### Application DNS when Route 53 is not set

Terraform creates Route 53 alias records only when `route53_zone_id` is set.
An empty zone does not publish `lde_domain` or `dtrack_domain`. After apply,
print the load balancer name and create one CNAME for each hostname in the DNS
service that already hosts those names:

```bash
terraform output -raw alb_dns_name
```

| Name | Type | Target | Proxy |
|---|---|---|---|
| `lde_domain` | CNAME | the `alb_dns_name` output | off |
| `dtrack_domain` | CNAME | the same output | off |

Leave the proxy off. A proxied name presents the DNS provider's addresses, and
an allowlist of one client `/32` then rejects the browser. An ACM validation
CNAME is a different record: its name starts with `_`. Do not change it. A
public CNAME does not reach a load balancer that still has `alb_internal = true`.

A rebuilt stack gets a new `alb_dns_name`. CNAMEs left from an earlier stack
still name the deleted load balancer: edit their target. Confirm both names
resolve to the output:

```bash
terraform output -raw alb_dns_name
dig +short lde.example.com dtrack.example.com   # each name's first line: that output
```

---

## Step 4 — Populate secrets

<!-- updated: separate the two browser logins from the API tokens -->

Two browser prompts. They do not share a password. Terraform does not create either password.

| Prompt | Username | What you type as the secret | Where it is stored |
|---|---|---|---|
| `https://lde.example.com` | The JSON key you choose. The commands below use `admin`. | The plaintext password you hashed. The browser does not want the hash. | `lde/basic-auth`, as `{"admin": "<sha256 hex>"}` |
| `https://dtrack.example.com` | `admin` | `admin` on the first visit, then the new password Dependency-Track asks you to set | Dependency-Track's database. Not `lde/basic-auth`. |

Anything else is not a login for those prompts:

| Value | Used for | Secret |
|---|---|---|
| GitHub fine-grained PATs | One per org: the resource owner is the org whose repos you scan, not your user account. | `lde/github-pat`, a JSON object `{"<org>": "<token>"}` |
| Dependency-Track API key | Created by `scripts/bootstrap_dtrack.py` in Step 5 | `lde/dtrack-api-key` |
| Gemini API key | Package-name extraction only. Skip it until you use that feature. | `lde/gemini-api-key` |

The Aurora master password and the AWS console password do not open either site.

Step 3 writes `lde/basic-auth` before plan. The other three `lde/*` shells start as `REPLACE_ME`. The running task reads Secrets Manager within a minute. A new ECS deployment is not required.

> **Stop here and set the values.** Do not put them in a `.tf` file or commit them.

`lde/basic-auth` stays on `scripts/set_lde_password.py` (Step 3). `lde/dtrack-api-key` is what the bootstrap script writes in Step 5. Write the GitHub PAT and Gemini key with the commands below. `tr -d '\n'` is required because `op item get` prints a trailing newline. LDE reads the secret within a minute.

Sign in to the 1Password CLI first: turn on 1Password → Settings → Developer →
**Integrate with 1Password CLI**, or run `op signin`. Then find each item's ID
and the label of the field that holds the token. Both commands print names only:

```bash
op item list --vault <vault-name> | grep -iE 'github|gemini'
op item get <item-id> --vault <vault-name> --format json | jq -r '.fields[].label'
```

The commands below read the field labelled `password`. Replace it when the
token sits under another label, such as `credential`. Use the item ID rather
than its title: titles with spaces or `#` break the quoting. Paste each command
whole; a line that wraps without its trailing `\` splits the pipe and writes
nothing.

### GitHub PATs

One fine-grained PAT per org, written as one JSON object. Requires `jq`. Add one `--arg` and one
key per org; each org's key must match its GitHub name.

```bash
jq -n \
  --arg a "$(op item get <item-id-a> --vault <vault-name> --fields label=password --reveal)" \
  --arg b "$(op item get <item-id-b> --vault <vault-name> --fields label=password --reveal)" \
  '{"example-org": $a, "another-org": $b}' \
  | tr -d '\n' \
  | aws secretsmanager put-secret-value \
      --secret-id lde/github-pat \
      --secret-string file:///dev/stdin \
      --region us-east-1
```

To use one token (for example a classic PAT that spans orgs) for every org without its own entry, add a `"*"` key. An org with neither is an error.

### Gemini API key

Skip this until you use Gemini package-name extraction. `REPLACE_ME` is not a key.

```bash
op item get <item-id> --vault <vault-name> --fields label=password --reveal \
  | tr -d '\n' \
  | aws secretsmanager put-secret-value \
      --secret-id lde/gemini-api-key \
      --secret-string file:///dev/stdin \
      --region us-east-1
```

Leave `lde/dtrack-api-key` as `REPLACE_ME` until Step 5. That key is not the DT UI password.

---

## Step 5 — First boot

### Services already running

Step 3 started the services. Service names use `var.env` (`dev` in the example). Writing a secret does not require `update-service`. LDE loads `lde/github-pat`, `lde/basic-auth`, `lde/dtrack-api-key`, and `lde/gemini-api-key` from Secrets Manager and reuses each value for up to 60 seconds.

### Tail logs

```bash
aws logs tail /ecs/dev-lde-dtrack-api --follow --region us-east-1

aws logs tail /ecs/dev-lde --follow --region us-east-1
```

### Bootstrap Dependency-Track

Confirm the API is reachable, then run the bootstrap script. The stock Automation team lacks `PROJECT_CREATION_UPLOAD`; the script grants it. `VIEW_PORTFOLIO` is already granted and is what package search uses.

```bash
# Wait until this returns HTTP 200
curl -sI "https://dtrack.example.com/api/version"

# Fresh install still has admin / admin until the script rotates it.
DTRACK_ADMIN_PASSWORD=admin python3 scripts/bootstrap_dtrack.py \
  --url "https://dtrack.example.com" \
  --password-out ~/.lde/dtrack-admin.aws.txt \
  --secret-id lde/dtrack-api-key \
  --region us-east-1
```

The script writes `~/.lde/dtrack-admin.aws.txt` (mode 0600). Keep `--password-out`: the default, `~/.lde/dtrack-admin.txt`, is the local instance's login and would be overwritten. The script also stores the new API key in `lde/dtrack-api-key`, and prints the team name, permission names, key prefix, and key length — never the password or the key. LDE reads `lde/dtrack-api-key` within a minute: wait that long before Step 6. Do not force a new LDE deployment for this.

The script also applies Dependency-Track's cost settings: the metrics jobs run every 24 hours instead of hourly, and vulnerability mirroring (NVD, EPSS) and analysis are off, because LDE never reads vulnerabilities. It prints one `setting:` line for each. Dependency-Track reads its scheduler settings at startup, so force one new deployment of the API service afterwards:

```bash
aws ecs update-service --cluster "$ECS_CLUSTER" --service dev-lde-dtrack-api \
  --force-new-deployment --region us-east-1
```

To re-apply only the settings to a running instance, pass `--password-file ~/.lde/dtrack-admin.aws.txt --settings-only`. See [AWS cost control](aws-cost-control.md).

If you already changed the admin password in the browser, pass that password via `DTRACK_ADMIN_PASSWORD` or `--password-file`. A login that returns HTTP 401 without body `FORCE_PASSWORD_CHANGE` exits without rotating the password.

---
## Step 6 — Smoke tests

Run the read-only check first. It covers the ECS services, target health, DNS,
the shape of each `lde/*` secret (never its value), the Basic Auth gate, and the
GitHub, Dependency-Track and Gemini status endpoints:

```bash
python3 scripts/check_aws.py verify   # exit 1 on any FAIL line
```

Then run these against the live ALB URL:

```bash
ALB="https://lde.example.com"
BASIC_AUTH="admin:yourpassword"   # JSON key, then the plaintext password. Not the stored hash. Not the DT password.

# 1. Basic Auth gate (GET: LDE answers HEAD requests with 501)
curl -s -o /dev/null -w '%{http_code}\n' "$ALB"                     # expect 401
curl -s -o /dev/null -w '%{http_code}\n' -u "$BASIC_AUTH" "$ALB"    # expect 200

# 2. GitHub PAT status
curl -su "$BASIC_AUTH" "$ALB/api/gh-status" | python3 -m json.tool

# 3. Settings shows DT URL
curl -su "$BASIC_AUTH" "$ALB/api/settings" | python3 -m json.tool

# 4. Package search (must return results if DT has data)
curl -su "$BASIC_AUTH" -X POST "$ALB/api/dtrack/package-search" \
  -H 'Content-Type: application/json' \
  -d '{"packages":["lodash"]}' | python3 -m json.tool

# 5. Trigger a single-repo SBOM ingest (replace org/repo)
curl -su "$BASIC_AUTH" -X POST "$ALB/api/runs" \
  -H 'Content-Type: application/json' \
  -d '{"repos":["your-org/your-repo"],"method":"github_sbom"}' | python3 -m json.tool
# → note the run_id

# 6. Poll until the run completes
RUN_ID="<run_id_from_step_5>"
curl -su "$BASIC_AUTH" "$ALB/api/runs/$RUN_ID" | python3 -m json.tool
```

Dependency-Track indexes components a few seconds after a BOM upload. Search
for a package from the ingested repo once the run completes; an empty
`matches` list right after the run can be the index catching up. Retry after
30 seconds before treating it as a failure.

---

## Ongoing deployments

```bash
cd library-dependency-explorer
ECR_URL=$(terraform -chdir=terraform output -raw ecr_repo_url)
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin "$ECR_URL"

# Build HEAD for Fargate x86 tasks. The repository is IMMUTABLE: commit
# first, because a pushed tag cannot be pushed again.
GIT_SHA=$(git rev-parse --short HEAD)
BUILD_DIR=$(mktemp -d)
git archive HEAD | tar -x -C "$BUILD_DIR"
docker build --platform linux/amd64 -t lde:latest "$BUILD_DIR"
docker tag lde:latest "$ECR_URL:$GIT_SHA"
docker push "$ECR_URL:$GIT_SHA"

# Update terraform.tfvars with the new image tag
sed -i '' "s|lde_image = .*|lde_image = \"$ECR_URL:$GIT_SHA\"|" terraform/terraform.tfvars

# Plan the new task definition and service, read the plan, then apply it.
# Expect the lde task definition replaced and aws_ecs_service.lde updated
# in place. Terraform registers the revision and updates the service: no
# manual aws ecs update-service required.
cd terraform
terraform plan -target=aws_ecs_task_definition.lde -target=aws_ecs_service.lde -out=deploy.tfplan
terraform apply deploy.tfplan
cd .. && python3 scripts/check_aws.py verify   # LDE runs lde_image <GIT_SHA>
```

Terraform plans the working tree. An uncommitted `.tf` change goes out with the
next plan even though the image comes from `HEAD`: commit or set it aside first.

Terraform will wait for the new task to pass health checks (`wait_for_steady_state = true`)
before returning. If it doesn't become healthy within ~15 minutes, the deployment times out
and you can investigate via ECS Exec or CloudWatch logs.

---

## ECS Exec (live shell for debugging)

```bash
ECS_CLUSTER=$(sed -n 's/^ecs_cluster_name *= *"\(.*\)".*/\1/p' "$(git rev-parse --show-toplevel)/terraform/terraform.tfvars")
TASK_ID=$(aws ecs list-tasks --cluster "$ECS_CLUSTER" --service-name dev-lde \
  --query 'taskArns[0]' --output text --region us-east-1)

aws ecs execute-command \
  --cluster "$ECS_CLUSTER" \
  --task "$TASK_ID" \
  --container lde \
  --interactive \
  --command "/bin/sh" \
  --region us-east-1
```

---

## Teardown

`terraform destroy` is not enough on its own. Run these before it. `dev-lde`
below is `local.name_prefix` when `env` is `dev`.

1. Delete the application CNAMEs you created for `lde_domain` and
   `dtrack_domain`. Terraform does not own them. Leave every validation CNAME
   whose name starts with `_`.
2. Turn off deletion protection. Both switches are hardcoded on, so
   `terraform destroy` fails until AWS shows them off.

```bash
ALB_ARN=$(aws elbv2 describe-load-balancers --names dev-lde \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text)
aws elbv2 modify-load-balancer-attributes --load-balancer-arn "$ALB_ARN" \
  --attributes Key=deletion_protection.enabled,Value=false

aws rds modify-db-cluster --db-cluster-identifier dev-lde-dtrack \
  --no-deletion-protection --apply-immediately
```

3. `aws_ecr_repository.lde` is `IMMUTABLE`. Delete the images or destroy
   cannot delete the repository.

```bash
aws ecr list-images --repository-name dev-lde \
  --query 'imageIds[].imageDigest' --output text \
| tr '\t' '\n' \
| while read -r digest; do
    [ -n "$digest" ] || continue
    aws ecr batch-delete-image --repository-name dev-lde \
      --image-ids imageDigest="$digest"
  done
```

4. From `terraform/`, run `terraform destroy`.
5. Destroy creates the Aurora snapshot `dev-lde-dtrack-final`
   (`final_snapshot_identifier` in `terraform/rds.tf`). Delete it or the next
   destroy fails on that fixed name.

```bash
aws rds delete-db-cluster-snapshot \
  --db-cluster-snapshot-identifier dev-lde-dtrack-final
```

6. The four `lde/*` secrets set `recovery_window_in_days = 7`. Destroy does
   not free the names. Force-delete each one or the next apply cannot create
   the shells.

```bash
aws secretsmanager delete-secret --secret-id lde/github-pat \
  --force-delete-without-recovery
aws secretsmanager delete-secret --secret-id lde/dtrack-api-key \
  --force-delete-without-recovery
aws secretsmanager delete-secret --secret-id lde/gemini-api-key \
  --force-delete-without-recovery
aws secretsmanager delete-secret --secret-id lde/basic-auth \
  --force-delete-without-recovery
```

7. The ECS cluster is not in this module. Delete the name you passed as
   `ecs_cluster_name`:

```bash
ECS_CLUSTER=$(sed -n 's/^ecs_cluster_name *= *"\(.*\)".*/\1/p' "$(git rev-parse --show-toplevel)/terraform/terraform.tfvars")
aws ecs delete-cluster --cluster "$ECS_CLUSTER"
```

The name stays `INACTIVE` until you do. The next deploy must create it again
and see `ACTIVE`.
8. The state bucket is not a Terraform resource. Leave it if you will apply
   again. To remove it, delete every object version and delete marker first.
   `aws s3 rb s3://<bucket> --force` fails with `BucketNotEmpty` while any
   version remains.

## Troubleshooting

### `terraform init` fails — backend credentials

If Terraform cannot find AWS credentials when initializing the S3 backend:

```bash
export AWS_PROFILE=your-profile
terraform init
```

The S3 backend does not inherit the profile from the `provider` block — it must be set
via `AWS_PROFILE` or added as `profile = "your-profile"` inside the `backend "s3" {}`
block in `terraform.tf`.

### Targeted apply fails — moved resource instances

`terraform apply -target=...` fails with `Moved resource instances excluded by
targeting` when the code holds a `moved` block that state has not applied yet.
Run an untargeted plan, read it, and apply that plan. It carries the move and
the image change together:

```bash
cd terraform
terraform plan -out=deploy.tfplan
terraform apply deploy.tfplan
```

### Docker image platform mismatch

If ECS shows a task failing with a platform or exec format error, the image was built
without the `--platform linux/amd64` flag. Rebuild and re-push:

```bash
ECR_URL=$(terraform -chdir=terraform output -raw ecr_repo_url)
GIT_SHA=$(git rev-parse --short HEAD)
BUILD_DIR=$(mktemp -d)
git archive HEAD | tar -x -C "$BUILD_DIR"
docker build --platform linux/amd64 -t lde:latest "$BUILD_DIR"
docker tag lde:latest "$ECR_URL:$GIT_SHA"
docker push "$ECR_URL:$GIT_SHA"
```

The repository is `IMMUTABLE`, so the push fails when that tag already holds
the broken image. Tag the rebuild `"$GIT_SHA-2"` instead, and set `lde_image`
to that tag.

### ACM certificate validation — two hosted zones

The ALB is internal, so its Route53 A records live in a **private** hosted zone.
ACM DNS validation requires the validation CNAME to be reachable from the public
internet — it cannot use a private zone.

Set `certificate_zone_id_override` in `terraform.tfvars` to the **public** hosted
zone ID so Terraform creates the ACM validation record there while A records go into
the private zone (`route53_zone_id`):

```hcl
route53_zone_id              = "Z0XXXXXXXXXXXXXXXXXX"   # private zone — A records
certificate_zone_id_override = "Z0YYYYYYYYYYYYYYYYYY"  # public zone — ACM CNAME
```

Both variables must be set when using separate zones. If you use a single public zone
for everything, set only `route53_zone_id` and leave `certificate_zone_id_override` empty.
