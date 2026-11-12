# Runbook: Secrets Rotation (Fargate)

Applies to the AWS ECS Fargate deployment.
For local development, update `.settings.json` directly — no restart required.

---

## How credential reloading works

`settings.py::load_settings()` is called on **every inbound request** — it calls
`secrets_loader.overlay()` each time, which reads the Secrets Manager values and reuses
each one for 60 seconds. This means a rotated secret is picked up within a minute after
AWS propagates the new value. **No ECS task restart is needed** for any of the secrets below.
To confirm a rotation, wait a minute before testing.

---

## Secrets managed in this deployment

| Secret ID | Setting key | What it authenticates |
|---|---|---|
| `lde/github` | `github_secret` | GitHub API: the org map, with each org's app key or (deprecated) PAT. Written by LDE from Settings. |
| `lde/github-pat` | `github_pats` | **Old.** Read only until `lde/github` is written; then `REPLACE_ME` |
| `lde/dtrack-api-key` | `dtrack_api_key` | Dependency-Track API — BOM upload, component search |
| `lde/gemini-api-key` | `gemini_api_key` | Google Gemini — package extraction from URLs/files |
| `lde/basic-auth` | `basic_auth_credentials` | HTTP Basic Auth gate on all LDE endpoints |

---

## Before you start

Confirm the current credentials are working:

```bash
ALB="https://lde.yourdomain.com"
BASIC_AUTH="admin:currentpassword"

# GitHub App and per-org status
curl -su "$BASIC_AUTH" "$ALB/api/gh-status" | python3 -m json.tool
# Expect: "logged_in": true

# DT connectivity (should return components or an empty array, not 503)
curl -su "$BASIC_AUTH" -X POST "$ALB/api/dtrack/package-search" \
  -H 'Content-Type: application/json' \
  -d '{"packages":["lodash"]}' | python3 -m json.tool
```

---

## Rotating a GitHub App private key

Each app has its own key; rotate them one at a time. GitHub lets an app hold more than one key,
so rotate without downtime:

1. On the app's settings page (github.com → owner → Settings → Developer settings → GitHub Apps
   → the app), click **Generate a private key**. GitHub downloads the new `.pem`.

2. Replace that app's `private_key` in `lde/github`. An org's own app is under
   `.orgs["<org>"]`; the enterprise app is `.enterprise_app`. Requires `jq`. The temporary file
   holds every key and PAT in the map: keep it in `$TMPDIR` and delete it.

   ```bash
   aws secretsmanager get-secret-value --secret-id lde/github \
       --query SecretString --output text --region us-east-1 --profile your-profile \
       > "$TMPDIR/lde-github.json"
   jq --arg org <org> --rawfile key ~/Downloads/<new-key>.pem \
       '.orgs[$org].private_key = $key' "$TMPDIR/lde-github.json" \
     | tr -d '\n' \
     | aws secretsmanager put-secret-value \
         --secret-id lde/github \
         --secret-string file:///dev/stdin \
         --region us-east-1 --profile your-profile
   rm -f "$TMPDIR/lde-github.json"
   ```

   For the enterprise app, use `'.enterprise_app.private_key = $key'`. Locally, overwrite the
   app's key file and keep it `chmod 600`.

3. Wait a minute, then verify:

   ```bash
   curl -su "$BASIC_AUTH" "$ALB/api/gh-status" | python3 -m json.tool
   # Expect: "logged_in": true, and "ok": true on every org that uses the app
   ```

4. Delete the old key on the app's settings page, then delete the downloaded `.pem`.

Tokens already minted with the old key stay valid until they expire (at most an hour).

---

## Rotating an org's PAT (deprecated)

Prefer creating a GitHub App for the org, which replaces its PAT ([GitHub App](github-app.md#migrate-from-pats)).

1. Generate a new fine-grained PAT on GitHub:
   - Settings → Developer settings → Personal access tokens → Fine-grained tokens
   - Expiration: 90 days (or per policy)
   - Repository access: All repositories (or select specific orgs)
   - Permissions: Contents — Read-only, Metadata — Read-only

2. For each SSO org, authorize the new token:
   - github.com → Settings → Personal access tokens → authorize each org

3. In LDE, open **Settings → GitHub auth**, type the new token into the org's row and click
   **Save**. This works locally and on AWS, where LDE writes `lde/github`. Or call the API:

   ```bash
   curl -su "$BASIC_AUTH" -X PUT "$ALB/api/github/orgs/example-org" \
     -H 'Content-Type: application/json' \
     -d '{"auth": "pat", "token": "github_pat_XXXX..."}'
   ```

4. Verify:

   ```bash
   curl -su "$BASIC_AUTH" "$ALB/api/gh-status" | python3 -m json.tool
   # Expect: "ok": true on the org's entry in "orgs"
   ```

5. Revoke the old PAT on GitHub.

---

## Rotating `dtrack_api_key`

1. In the Dependency-Track UI (`https://dtrack.yourdomain.com`):
   - Administration → Access Management → Teams → Automation
   - Click **+** next to API Keys to generate a new key
   - Copy the new key

2. Put it in Secrets Manager:

   ```bash
   aws secretsmanager put-secret-value \
     --secret-id lde/dtrack-api-key \
     --secret-string "dt_key_XXXX..." \
     --region us-east-1 --profile your-profile
   ```

3. Verify DT connectivity:

   ```bash
   curl -su "$BASIC_AUTH" -X POST "$ALB/api/dtrack/package-search" \
     -H 'Content-Type: application/json' \
     -d '{"packages":["lodash"]}' | python3 -m json.tool
   # Expect: results array (may be empty if lodash isn't indexed, but not 503)
   ```

4. In the DT UI, delete the old API key from the Automation team.

---

## Rotating `gemini_api_key`

1. Generate a new key in Google AI Studio or the Google Cloud console.

2. Put it in Secrets Manager:

   ```bash
   aws secretsmanager put-secret-value \
     --secret-id lde/gemini-api-key \
     --secret-string "AIza..." \
     --region us-east-1 --profile your-profile
   ```

3. Verify (extraction requires a URL with extractable package names):

   ```bash
   curl -su "$BASIC_AUTH" -X POST "$ALB/api/extract-packages" \
     -H 'Content-Type: application/json' \
     -d '{"url": "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw"}' \
     | python3 -m json.tool
   # Note the task_id, then poll:
   TASK_ID="<task_id>"
   curl -su "$BASIC_AUTH" "$ALB/api/tasks/$TASK_ID" | python3 -m json.tool
   # Expect: status: completed, result: [array of package names]
   ```

4. Disable the old key in the Google console.

---

## Rotating the Basic Auth password

Basic Auth credentials are stored as a JSON string of `{username: sha256_hex}` pairs.

1. Generate the new hash on your local machine (not in a CI log):

   ```bash
   python3 -c "
   import hashlib, json, getpass
   pw = getpass.getpass('New password: ')
   print(json.dumps({'admin': hashlib.sha256(pw.encode()).hexdigest()}))
   "
   ```

2. Put the JSON string in Secrets Manager:

   ```bash
   aws secretsmanager put-secret-value \
     --secret-id lde/basic-auth \
     --secret-string '{"admin":"<sha256_hex>"}' \
     --region us-east-1 --profile your-profile
   ```

3. Verify with the new password:

   ```bash
   curl -sI -u "admin:newpassword" "$ALB"   # expect 200
   curl -sI -u "admin:oldpassword" "$ALB"   # expect 401
   ```

> The old password stops working within a minute of AWS propagating the new secret
> value — no restart required because credentials are reloaded per-request, and each
> Secrets Manager value is reused for at most 60 seconds.

---

## Aurora PostgreSQL password rotation (dtrack-api outage)

The `rds!cluster-*` Secrets Manager secret is managed by RDS, not LDE. It rotates
automatically on a schedule (currently every 30 days). Unlike the LDE secrets above,
**the dtrack-api ECS task does not re-read this secret at runtime** — `ALPINE_DATABASE_PASSWORD`
is injected once at task launch. When the secret rotates, the running task holds a stale
password and Aurora rejects every connection with:

```
FATAL: password authentication failed for user "dtrack"
```

The Dependency-Track UI becomes inaccessible and LDE's BOM uploads fail.

### Detect

```bash
aws logs tail /ecs/dev-lde-dtrack-api --since 15m --region us-east-1 \
  | grep "password authentication"
```

### Fix — force-redeploy dtrack-api

```bash
aws ecs update-service \
  --cluster your-ecs-cluster \
  --service dev-lde-dtrack-api \
  --force-new-deployment \
  --region us-east-1 --profile your-profile
```

The new task fetches `AWSCURRENT` from the rotated secret at startup. Confirm recovery:

```bash
aws logs tail /ecs/dev-lde-dtrack-api --since 3m --region us-east-1 \
  | grep -E "Dependency-Track is ready|password authentication"
# Expect: "Dependency-Track is ready" with no auth failures from the new task ID
```

### Check rotation schedule

```bash
aws secretsmanager describe-secret \
  --secret-id "$(aws rds describe-db-clusters --region us-east-1 \
      --query 'DBClusters[?contains(DBClusterIdentifier,`lde`)].MasterUserSecret.SecretArn' \
      --output text)" \
  --region us-east-1 --profile your-profile \
  --query '{NextRotation:NextRotationDate,LastRotated:LastRotatedDate,AutoRotateDays:RotationRules.AutomaticallyAfterDays}'
```

### Adjust rotation window

```bash
aws secretsmanager rotate-secret \
  --secret-id <arn-from-above> \
  --rotation-rules AutomaticallyAfterDays=30 \
  --no-rotate-immediately \
  --region us-east-1 --profile your-profile
```

Also update `terraform/rds.tf` (`manage_master_user_password_rotation_automatically_after_days`)
so a future `terraform apply` does not revert the window.

---

## Rollback

If the new credential doesn't work, restore the previous version:

Replace `lde/github` with the secret you rotated (for example `lde/dtrack-api-key`).

```bash
# List previous versions
aws secretsmanager list-secret-version-ids \
  --secret-id lde/github \
  --region us-east-1 --profile your-profile

# Restore a specific version
VERSION_ID="<version-id-from-above>"
aws secretsmanager put-secret-value \
  --secret-id lde/github \
  --secret-string "$(aws secretsmanager get-secret-value \
      --secret-id lde/github \
      --version-id "$VERSION_ID" \
      --region us-east-1 --profile your-profile \
      --query SecretString --output text)" \
  --region us-east-1 --profile your-profile
```

AWS Secrets Manager retains previous versions until you explicitly delete them.
