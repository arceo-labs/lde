# AWS Cost Control

This page records what the AWS stack costs, why, what was changed to cut the bill, and the options held back for later. Use it before resizing a task, changing a Dependency-Track setting, or estimating a new deployment.

The figures come from the `dev` stack in `us-east-1`, first deployed 2026-10-14 03:05 UTC. Measurement used AWS Cost Explorer and CloudWatch for the first 39 hours, plus the Dependency-Track 4.14.5 source. A month is 730 hours. Prices are on-demand and exclude tax.

## Summary

| State | Full stack | Dependency-Track only (LDE runs locally) |
|---|---|---|
| Before this round | ~$202 / month | ~$175 / month |
| After this round | ~$133 / month | ~$117 / month |
| With RDS, ARM64 and Fargate Spot (deferred) | ~$75 / month | ~$67 / month |

Four causes account for most of the spend above the base cost of running the stack:

1. Dependency-Track ran its metrics jobs hourly. Each run pushed Aurora to its 4 ACU maximum.
2. Dependency-Track re-parsed the full NVD feed about every six days. LDE never reads vulnerabilities, so vulnerability mirroring and analysis are now off.
3. Every ALB health check made LDE fetch four secrets from Secrets Manager.
4. The LDE and Dependency-Track API tasks were sized at two to five times their measured use.

## Architecture and billed items

```
  Internet ──► ALB (2 public IPv4, one per AZ) ──┬──► LDE task (public IPv4)
                                                 │      └── EFS /app/data
                                                 ├──► DT frontend task (public IPv4)
                                                 └──► DT API task (public IPv4)
                                                        └── Aurora Serverless v2
  LDE ──► Secrets Manager (4 lde/* secrets)
  DT API ──► NVD, GitHub Advisories, EPSS (internet, via its public IPv4)
```

Every task runs in a public subnet with `assign_public_ip = true`. No NAT gateway exists, so each task needs its own public address to pull images and reach the internet.

## Where the money went (before this round)

| Item | Measured use | Rate | USD / month |
|---|---|---|---|
| Aurora compute | 0.85 ACU average (0.5 minimum) | $0.12 / ACU-hour | 74.46 |
| Aurora I/O | ~63k I/Os per hour | $0.20 / million | 9.26 |
| Aurora storage | 1.9 GB | $0.10 / GB-month | 0.19 |
| NVD full re-parse | ~2.5 h at ~3 ACU and ~9.6M I/Os, every ~6 days | as above | ~13.30 |
| Fargate: LDE | 0.5 vCPU / 1 GB | $0.04048 / vCPU-hour, $0.004445 / GB-hour | 18.02 |
| Fargate: DT API | 1 vCPU / 2 GB | as above | 36.04 |
| Fargate: DT frontend | 0.25 vCPU / 0.5 GB (Fargate minimum) | as above | 9.01 |
| ALB | 1 load balancer, ~0.01 LCU-hours a day | $0.0225 / hour | 16.50 |
| Public IPv4 | 5 addresses: 2 ALB, 3 tasks | $0.005 / hour each | 18.25 |
| Secrets Manager storage | 5 secrets (4 `lde/*`, 1 RDS-managed) | $0.40 / secret-month | 2.00 |
| Secrets Manager API | ~24,500 calls a day | $0.05 / 10,000 | 3.72 |
| Route 53, S3, ECR, EFS, CloudWatch Logs | private zone `dev-lde.local`, ALB logs, 274 MB of images | | ~1.00 |
| **Total** | | | **~$202** |

The first boot also costs about $3 once, when Dependency-Track loads the NVD for the first time.

## Findings

### 1. Metrics jobs ran hourly

Dependency-Track's `PortfolioMetricsUpdateTask` and `VulnerabilityMetricsUpdateTask` ran at minute :14 of every hour. Each run took about 18 seconds. Aurora went to 4 ACU at 100% CPU, then took about 20 minutes to scale back down:

| Minutes past the hour | Average ACU |
|---|---|
| :00–:14 | 0.50 |
| :14–:40 | 1.31 |
| :40–:60 | 0.50 |

That pattern accounts for all of the 0.35 ACU above the 0.5 minimum, about $29 a month.

`terraform/ecs.tf` set `TASK_SCHEDULER_PORTFOLIO_METRICS_UPDATE_CADENCE=24` and `TASK_SCHEDULER_VULNERABILITY_METRICS_UPDATE_CADENCE=24`. Dependency-Track ignores both. Since v4.6 it reads these cadences from its database (group `task-scheduler`, default `1` hour), and only at startup ([recurring tasks](https://docs.dependencytrack.org/getting-started/recurring-tasks/), [`ConfigPropertyConstants.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/model/ConfigPropertyConstants.java), [`TaskScheduler.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/tasks/TaskScheduler.java)).

### 2. The NVD feed mirror re-parsed everything about every six days

By default Dependency-Track mirrors the NVD by downloading one JSON feed per year into a `nist` directory under its data directory on `/data`. A yearly feed is treated as fresh for five days after it was last parsed. After that, the next nightly run downloads and parses every yearly feed again ([`NistMirrorTask.java` line 283](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/tasks/NistMirrorTask.java#L283)). The first full parse took 2 h 33 min (`Time spent (parse): 7972737ms`), with Aurora averaging 2.95 ACU and about 9.6 million I/Os. That costs about $2.66 per run, or about $13 a month.

`/data` is the task's ephemeral disk, so every Dependency-Track API restart or redeploy also triggers a full re-parse.

LDE uses Dependency-Track for projects, BOM uploads, project components and component search (`backend/dtrack_client.py`). It never reads vulnerabilities, findings, metrics or EPSS scores. So the fix is to stop mirroring and analysing vulnerabilities:

| Setting | Default | Set to | Stops |
|---|---|---|---|
| `vuln-source / nvd.enabled` | `true` | `false` | NVD mirror, feed or API |
| `vuln-source / nvd.api.enabled` | `false` | `false` | nothing now; prevents a full API catch-up if the NVD is turned back on |
| `vuln-source / epss.enabled` | `true` | `false` | EPSS download after each NVD run |
| `scanner / internal.enabled` | `true` | `false` | Matching every uploaded BOM against the mirrored CVEs |
| `scanner / ossindex.enabled` | `true` | `false` | OSS Index analysis (it skipped every upload anyway: no token) |

GitHub Advisories, OSV, VulnDB, Snyk and Trivy are off by default. The vulnerabilities already loaded stay in the database (about 2 GB, ~$0.20 a month). The Dependency-Track UI shows no new findings.

If vulnerabilities are ever needed, use the NVD API mirror (`nvd.api.enabled = true`) rather than feed files. It fetches only CVEs modified since its last run and stores that position in the database, so restarts do not reset it ([`NistApiMirrorTask.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/tasks/NistApiMirrorTask.java)). Its first run fetches every CVE: measured on 2026-10-16 at 0.5 vCPU without an API key, about 4,500 CVEs a minute out of 408,723, with the API task at its CPU limit and Aurora at 2.0–2.4 ACU. Expect 1.5–2 hours. Leave the API key unset: Dependency-Track encrypts it with a key file under `/data`, which a restart replaces.

### 3. ALB health checks fetched secrets

The `dev-lde-lde-tg` health check calls `/api/settings` every 30 seconds from each ALB node. The auth check in `server.py` runs `load_settings()` before returning 401. That ran `secrets_loader.overlay()`, which fetched all four `lde/*` secrets with no cache. That added up to about 16 calls a minute.

### 4. Tasks were oversized

ECS service metrics, maximum per 5 minutes, from 2026-10-14 08:00 UTC onward:

| Service | Size | CPU average | CPU p95 | CPU max | Memory max |
|---|---|---|---|---|---|
| `dev-lde` | 0.5 vCPU / 1 GB | 4.7% | 6.7% | 26% at startup | 10.5% |
| `dev-lde-dtrack-api` | 1 vCPU / 2 GB | 2.9% | 13.4% | 57% (BOM upload) | 28% |
| `dev-lde-dtrack-frontend` | 0.25 vCPU / 0.5 GB | 0.02% | 0.03% | 0.8% | 0.65% |

During the first NVD load, the API task averaged 26% CPU (0.26 vCPU), with p90 34% and memory at most 30%. Aurora, not the API task, set the pace of that load.

### 5. Five public IPv4 addresses

The ALB holds two addresses. An ALB needs subnets in at least two Availability Zones, puts a node in each one, and gives each node one IP address ([Availability Zone subnets](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#availability-zones), [DNS name](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#dns-name)). Those are AWS-managed Elastic IPs ([IP address management](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#w2aab7c21)), billed like any other public IPv4 address ([VPC pricing](https://aws.amazon.com/vpc/pricing/)). The other three belong to the tasks.

### 6. Aurora does not pause

Aurora Serverless v2 bills per second for the ACUs in use and scales with CPU, memory and network demand between `db_instance_class` (0.5) and `db_max_acus` (4). Auto-pause needs zero connections. Dependency-Track keeps a pool of 10 to 20 connections open the whole time (`DatabaseConnections` stays at 20), so Aurora never reaches zero.

## Changes in this round

| Change | Files | Saves / month |
|---|---|---|
| Metrics jobs every 24 hours | `scripts/bootstrap_dtrack.py` (`COST_SETTINGS`), applied with `--settings-only` | ~$29 |
| Vulnerability mirroring and analysis off (NVD, EPSS, internal and OSS Index analyzers) | `scripts/bootstrap_dtrack.py` (`COST_SETTINGS`) | ~$13 |
| DT API 1 → 0.5 vCPU, 2 GB kept | `terraform/ecs.tf` | ~$15 |
| LDE 0.5 vCPU / 1 GB → 0.25 vCPU / 0.5 GB | `terraform/ecs.tf` | ~$9 |
| Cache Secrets Manager values for 60 seconds | `backend/secrets_loader.py` | ~$3 |
| Pin `dependencytrack/apiserver` and `frontend` to `4.14.5` | `terraform/variables.tf` | none; a restart can no longer upgrade Dependency-Track |
| Remove the two ignored `TASK_SCHEDULER_*` env vars | `terraform/ecs.tf` | none |
| 180-second health-check grace period on the DT API service | `terraform/ecs.tf` | none; covers a slower JVM start at 0.5 vCPU |

Cached secrets change rotation timing: a rotated `lde/*` secret now takes effect within 60 seconds, not on the next request. See [Secrets rotation](runbook-secrets-rotation.md).

### Expected cost after this round

| Resource | Size | USD / month |
|---|---|---|
| Fargate: LDE, DT API, DT frontend | 0.25 + 0.5 + 0.25 vCPU, 0.5 + 2 + 0.5 GB | 39 |
| Aurora Serverless v2: compute, I/O, storage | ~0.52 ACU average | 55 |
| ALB | one, low LCU usage | 17 |
| Public IPv4 | 5 addresses | 18 |
| Secrets Manager | 5 secrets, ≤ 5,800 calls a day | 3 |
| Route 53, S3, ECR, EFS, CloudWatch Logs | small | 1 |
| **Total** | | **~133** |

The Aurora I/O figure assumes no reduction. Fewer metrics runs should lower it.

## Apply the changes

Run these phases in order. Each phase is self-contained.

### Phase 1 — Apply the Dependency-Track settings

Run this from a machine whose public IP is in `alb_ingress_cidr_blocks`. It logs in with the saved admin password, changes no password and creates no API key:

```bash
python3 scripts/bootstrap_dtrack.py \
  --url "https://dtrack.example.com" \
  --password-file ~/.lde/dtrack-admin.aws.txt \
  --settings-only
```

Expect seven `setting:` lines. Apply this before Phase 3: the scheduler reads its cadences only at startup, and a restart with the NVD still enabled costs another full NVD load.

A fresh deployment needs no separate step. `bootstrap_dtrack.py` in [AWS deployment Step 5](aws-deployment.md#step-5-first-boot) applies the same settings.

### Phase 2 — Build and push the LDE image

The Secrets Manager cache is a code change, so LDE needs a new image. Follow [Ongoing deployments](aws-deployment.md#ongoing-deployments) from a commit that contains this change, and set `lde_image` to the new short SHA.

### Phase 3 — Plan and apply

```bash
terraform -chdir=terraform init -backend-config=backend.hcl
python3 scripts/check_aws.py preflight
terraform -chdir=terraform plan -out=cost-control.tfplan
```

Confirm the plan replaces the three task definitions and updates the three services in place, with nothing destroyed except the old task definition revisions. Then apply:

```bash
terraform -chdir=terraform apply cost-control.tfplan
```

The DT API task restarts. It reads the new cadences at startup and runs no vulnerability mirror. Startup takes about 95 seconds at 0.5 vCPU.

### Phase 4 — Verify

```bash
python3 scripts/check_aws.py verify
```

Then confirm each change took effect:

```bash
# Metrics jobs: one run 10 seconds after startup, then none for 24 hours.
aws logs filter-log-events --log-group-name /ecs/dev-lde-dtrack-api \
  --start-time $(( ($(date +%s) - 7200) * 1000 )) \
  --filter-pattern '"Executing portfolio metrics update"' \
  --query 'events[].message' --output text

# Vulnerability mirrors: expect no output.
aws logs filter-log-events --log-group-name /ecs/dev-lde-dtrack-api \
  --start-time $(( ($(date +%s) - 7200) * 1000 )) \
  --filter-pattern '?NistMirrorTask ?NistApiMirrorTask ?EpssMirrorTask ?InternalAnalysisTask' \
  --query 'events[].message' --output text

# Aurora: hourly average ACU should sit at 0.5 outside the daily jobs.
aws cloudwatch get-metric-statistics --namespace AWS/RDS \
  --metric-name ServerlessDatabaseCapacity \
  --dimensions Name=DBClusterIdentifier,Value=dev-lde-dtrack \
  --start-time $(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 3600 --statistics Average \
  --query 'sort_by(Datapoints,&Timestamp)[].[Timestamp,Average]' --output text
```

On Linux, replace `date -u -v-24H` with `date -u -d '24 hours ago'`.

## Measure the bill again

Cost Explorer data lags by up to a day. Wait at least two full days after Phase 3, then compare daily cost by usage type:

```bash
aws ce get-cost-and-usage \
  --time-period Start=$(date -u -v-7d +%Y-%m-%d),End=$(date -u +%Y-%m-%d) \
  --granularity DAILY --metrics UnblendedCost UsageQuantity \
  --group-by Type=DIMENSION,Key=USAGE_TYPE \
  --query 'ResultsByTime[].{day:TimePeriod.Start,items:Groups[?to_number(Metrics.UnblendedCost.Amount)>`0.01`].[Keys[0],Metrics.UnblendedCost.Amount]}' \
  --output json
```

Each Cost Explorer API request costs $0.01.

Per-day targets after this round:

| Usage type | Before | Target |
|---|---|---|
| `Aurora:ServerlessV2Usage` | ~20 ACU-hours | ~12.5 ACU-hours |
| `USE1-Fargate-vCPU-Hours:perCPU` | ~42 hours | ~24 hours |
| `USE1-Fargate-GB-Hours` | ~84 hours | ~72 hours |
| `USE1-AWSSecretsManagerAPIRequest` | ~24,500 requests | ≤ 5,800 requests |

## Roll back

- **Settings:** run `--settings-only` with the `COST_SETTINGS` values changed back to the defaults in [Findings](#2-the-nvd-feed-mirror-re-parsed-everything-about-every-six-days) (cadences `1`), then force a new DT API deployment. Turning the NVD back on starts a full load.
- **Task sizes, image pins, grace period:** revert the commit, then plan, review and apply.
- **Secrets cache:** set `lde_image` back to the previous tag, then plan, review and apply.

## Deferred options

| Option | Saves / month | Why it waits |
|---|---|---|
| Replace Aurora with RDS PostgreSQL `db.t4g.small`, single-AZ, 20 GB gp3 | ~$25–29 | A database migration: dump and restore, downtime, a new rollback plan. List price is about $0.032 an hour plus $0.115 per GB-month. Check current pricing first. |
| Fargate Spot for all three services | up to ~$27 (70% of $39) | Tasks can be interrupted with two minutes' warning. Safe for a dev stack now that no vulnerability mirror runs after a restart. |
| DT API 0.5 → 0.25 vCPU, 2 GB kept | ~$7 | Fargate allows 0.25 vCPU with up to 2 GB. With no mirror, BOM processing is the only heavy work. Startup took 95 seconds at 0.5 vCPU and may pass the 180-second grace period at 0.25: test it on its own. |
| ARM64 (Graviton) | ~$8 | Both Dependency-Track images publish `linux/arm64`. LDE's Dockerfile pins `linux/amd64` and needs a multi-arch build first. ARM Fargate is about 20% cheaper. |
| Dependency-Track only in AWS, LDE local | ~$16 after this round | Terraform needs switches to drop the LDE service, its target group and listener rule, EFS and the `lde/*` secrets. Local LDE sets `dtrack_url` to `https://<dtrack_domain>` (see `.settings.json.example`), and its public IP must be in `alb_ingress_cidr_blocks`. |
| Stop the stack outside working hours | depends on hours | Scale services to zero and stop Aurora (it restarts by itself after seven days). The ALB and its two addresses still bill. |

## Rejected options

| Option | Why not |
|---|---|
| Run the frontend in the DT API task | Decided against: services stay separate. Both images also listen on 8080, and the frontend's nginx template hard-codes it. |
| One task for all three containers | Same decision. A restart of any container would restart Dependency-Track. |
| Private subnets with a NAT gateway | A NAT gateway costs about $33 a month before data processing, more than the three task addresses. |
| IPv6 instead of public IPv4 | github.com has no IPv6, so LDE still needs IPv4. An ALB with `dualstack-without-public-ipv4` accepts only IPv6 clients. |
| EFS for Dependency-Track's NVD files | Avoids the re-parse after a restart, but not the five-day re-parse. |
| NVD API mirror | Fixes both re-parses, but LDE does not use vulnerabilities. Its first load took the API task to its CPU limit for 1.5–2 hours. |
| An NVD API key | Encrypted with a key file on the ephemeral disk, so it stops decrypting after a restart. |

## References

- [Application Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html): subnets, nodes, IP addresses
- [Amazon VPC pricing](https://aws.amazon.com/vpc/pricing/): public IPv4 charge
- [Dependency-Track recurring tasks](https://docs.dependencytrack.org/getting-started/recurring-tasks/)
- Dependency-Track 4.14.5 source: [`ConfigPropertyConstants.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/model/ConfigPropertyConstants.java), [`TaskScheduler.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/tasks/TaskScheduler.java), [`NistMirrorTask.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/tasks/NistMirrorTask.java), [`NistApiMirrorTask.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/tasks/NistApiMirrorTask.java), [`ConfigPropertyResource.java`](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/java/org/dependencytrack/resources/v1/ConfigPropertyResource.java)
