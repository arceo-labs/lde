---
name: start-fresh-aws
description: Use when asked to stand up, push, ship, redeploy, reset or tear down LDE in AWS (ECS Fargate, Terraform), to stop its bill, or when the AWS site is slow, failing or wrong, or its DNS or an lde/* secret is.
---

# start-fresh-aws

`docs/aws-deployment.md` owns the commands. `scripts/check_aws.py` owns the checks: `preflight` before any plan, `verify` after any apply or secret change. Both are read-only and report secrets by shape only. This skill owns the judgement: the mode, what ships, the gates, and the steps only the user can run. The local companion is `start-fresh-local`.

## Steps

1. **Pick the mode.**

    | Request | Mode | Guide sections |
    |---|---|---|
    | stand up, deploy, with empty state | deploy | Prerequisites, then Steps 2–6 |
    | push, ship, redeploy a code change | redeploy | Ongoing deployments |
    | start fresh, reset, rebuild | reset | Teardown steps 2–6, then deploy |
    | tear down, stop the bill | teardown | Teardown, every step |

    A reset keeps the ECS cluster and retargets the existing CNAMEs; a teardown removes both. When the stack is in state, run `verify` before any reset or teardown and show the result, however the request is worded. A healthy stack with one bad line usually takes a targeted fix; the user picks.

2. **Settle what ships.** Read `git status`. The image is built from `git archive HEAD`, while Terraform plans the working tree: an uncommitted `.tf` change ships with the next plan. Ask which files this deploy carries, commit only those, and deploy from the current branch. The image tag is HEAD's short SHA, so deploy a commit that is on the remote. When `git status -sb` shows `ahead`, tell the user the deployed SHA exists only in this checkout until it is pushed, and build only on their go-ahead. Pushing the branch is the user's call.

3. **Preflight.** Run `terraform -chdir=terraform init -backend-config=backend.hcl`, then `python3 scripts/check_aws.py preflight`. Done when every FAIL line is fixed or put to the user.
    - `lde_image ... is not in ECR` is expected before the first push. Rerun preflight after the push.
    - `exists but is not in Terraform state`: an earlier stack is still there. Finishing its Teardown is a reset decision.
    - `WARN ... root user`: ask once per session whether to continue as root.

4. **Gate every apply and destroy**, the targeted ECR apply included. Save the plan (`plan -out`, or `plan -destroy -out`), show its add/change/destroy counts, resource types and ingress CIDRs with the guide's cost table, get the go-ahead, then apply that plan file. A go-ahead covers the plan it answered.
    - **Teardown:** name what is lost for good: the Dependency-Track database (projects and admin login), LDE run history on EFS, the four `lde/*` secrets, the ECR images. The ALB gets a new DNS name. Ask whether to copy `dev-lde-dtrack-final` to `dev-lde-dtrack-<date>` first; the copy bills until deleted.
    - A targeted apply that fails on `Moved resource instances excluded by targeting` needs an untargeted plan. It carries every pending `.tf` change: name each one when you show it.

5. **Hand over the user-run steps** as exact commands.
    - `python3 scripts/set_lde_password.py` prompts with getpass: it runs in the user's own terminal window, not through `!`. It replaces `~/.lde/basic-auth.json` and `~/.lde/lde-admin.txt`. Reuse the existing pair only when the user says so.
    - DNS outside Route 53: both CNAMEs to the new `alb_dns_name`, proxy off, `_` records untouched. Confirm with `dig +short`.
    - 1Password: `!` works. The user lists item IDs and field labels first (guide Step 4), then pastes each multi-line command whole. Load the Gemini key only when the user wants package extraction.

6. **Bootstrap Dependency-Track** (guide Step 5) once `/api/version` returns 200. Pass `--password-out ~/.lde/dtrack-admin.aws.txt`, and say beforehand that it replaces the previous AWS login in that file. The frontend service starts after the API: wait for it. Done when the script prints one `setting:` line per `COST_SETTINGS` entry and the API redeploy that guide step ends with is stable.

7. **Verify.** Run `python3 scripts/check_aws.py verify`. Done when it prints no FAIL lines; after a redeploy, `LDE runs lde_image <tag>` names the new SHA. Ingest only a repo the user names; package search can lag the run by about 30 seconds.

## When the site misbehaves

Run `verify` first. Then follow the request inward, from the ALB to LDE:

1. **ALB access logs** show requests that were slow, failed or never reached LDE: `s3://dev-lde-alb-logs-<account>/alb/AWSLogs/<account>/elasticloadbalancing/us-east-1/<yyyy>/<mm>/<dd>/`. Each file covers 5 minutes and lands about 5 minutes after that window closes. The gap between `request_creation_time` and `time` is how long the ALB held a request; `request_processing_time` stays near 0 even for a stalled upload. A `408` with `target_processing_time` of `-1` is an upload the ALB gave up on after its 60-second idle timeout, before LDE saw it. Browsers resend a 408 on their own, so a request that went through after a long wait shows as two lines: the 408, then a fast success.
2. **CloudWatch** `/ecs/dev-lde` shows what LDE did: tracebacks, and one `Gemini call:` line per call with `finishReason` and token counts. Use `aws logs filter-log-events --log-group-name /ecs/dev-lde --start-time <epoch ms>`.
3. **Reproduce locally** with the same input and model before calling it an AWS problem. The ALB is the only hop local runs lack.

## Handling secrets

Read secrets and `~/.lde/*` files inside a Python process, and print lengths, prefixes and names only. `~/.lde/lde-admin.txt` holds the LDE username, then the password: build the Basic Auth header in Python for any ad-hoc call.

## Report

The URLs, the file holding each login, the deployed image tag, the `verify` result, and the monthly cost from the guide's cost table. After a reset, Dependency-Track starts empty: projects come back by re-ingesting.

## Undo

- **Redeploy:** set `lde_image` back to the previous tag, then plan, show and apply.
- **Teardown:** the database, secrets and images are gone. Only a copied snapshot survives.
