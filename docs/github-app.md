# GitHub App authentication

LDE reads GitHub as GitHub Apps. The usual setup is one private app per org you scan: each app
is owned by its org and installed only there. **Settings → Create app for &lt;org&gt;** creates one
in a click. Optionally, one enterprise-owned app can cover every org in a GitHub Enterprise
Cloud enterprise instead.

For each org, LDE picks the app owned by that org, else any other configured app installed
there. It trades that app's key for a one-hour installation token and uses the token for every
GitHub call to the org.

Per-org PATs (`github_pats`, `lde/github-pat`) still work as a fallback for orgs no app covers.
They are deprecated and will be removed in a later release.

```
 .settings.json github_apps / lde/github-app
   [{owner, app_id, private key}, ...]
            │  org X → app owned by X, else any app installed on X
            ▼
   backend/gh_app.py ── sign app JWT (RS256, 9 min) ──────────┐
            │                                                 │
            │   GET  /orgs/{org}/installation         ◄───────┤ api.github.com
            │   POST /app/installations/{id}/access_tokens ◄──┘
            │        permissions: contents:read, metadata:read
            ▼
   installation token (1 h, cached in memory per app, refreshed 5 min early)
            │
            ▼
   backend/github_client.py ── trees, contents, SBOM, dependency compare
```

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.11+ | Same as the rest of LDE |
| `cryptography` | 46.0.3 | Signs the app JWT. `pip install -r requirements.txt` installs it; the Docker image already has it. **Create app** refuses to start without it. |
| GitHub org owner | — | Creates the org's app and installs it. Members who are not owners can request the install. |
| `LDE_ALLOWED_ORIGIN` | — | Any deployment not on `localhost`: the exact URL you open LDE at. The app's callback URL is built from it. Terraform sets it on AWS. |
| `jq` | 1.6+ | Apps added by hand on AWS only: edits the `lde/github-app` secret |

---

## Step 1 — Create an app for each org

Pick how the orgs you scan are covered:

| Orgs | Create | How |
|---|---|---|
| Any org, or your own account | One private app per org, owned by that org | **Create app for &lt;org&gt;** in Settings (below). Repeat per org. |
| Several orgs in one GitHub Enterprise Cloud enterprise (optional) | One private, enterprise-owned app | By hand, as an enterprise owner ([below](#optional-one-enterprise-owned-app)). GitHub's one-click flow cannot create enterprise-owned apps. |

Both can be mixed: an org with its own app uses it, and any other org falls through to the
enterprise app if it is installed there.

A private app can be installed only by the account that owns it. An enterprise-owned app can be
installed by any org in its enterprise and by no one outside it.

### Create it from LDE

1. Open LDE at the URL you normally use (`http://localhost:8002`, or your `lde_domain`), then go
   to **Settings**. The **GitHub auth** card lists every org in `default_orgs`, every PAT org and
   every app owner.
2. Next to an org without an app, click **Create app for &lt;org&gt;**. For an org not in the list,
   open **Create a GitHub App for another org**, enter the org (blank = your personal account)
   and an optional name, then click **Create GitHub App on GitHub**.
3. GitHub shows the app's name and its two read-only permissions. Click
   **Create GitHub App for &lt;org&gt;**. You must be an owner of that org.
4. GitHub sends you back to LDE, which adds the app to its list:
   - Locally: the key goes to a new file `~/.lde/github-app-<id>.pem` (mode 0600), and
     `{"owner", "app_id", "private_key_path"}` is appended to `github_apps` in `.settings.json`.
   - AWS: `{"owner", "app_id", "private_key"}` is appended to the `lde/github-app` secret. The
     ECS task role may write that one secret and no other.

   The key never passes through your browser. LDE throws away the client secret and webhook
   secret GitHub also returns. The owner LDE records is the one GitHub reports for the new app.
5. LDE then sends you to the app's install page: continue with Step 2.

LDE only ever adds an app. It refuses to create a second app for an org that already has one,
and refuses any new app while the app config is broken.

| Back on Settings with | Fix |
|---|---|
| `setup link was unknown, already used or expired` | Start again from Settings. Each link works once, for an hour, and does not survive an LDE restart. |
| `GitHub did not hand over the new app` | Start again. GitHub's one-time code expires after an hour. Delete the half-made app on GitHub if it exists. |
| `could not store the new app's private key` | Check the server log. On AWS the task role needs `secretsmanager:PutSecretValue` on `lde/github-app` (`terraform apply`). Delete the unused app on GitHub, then start again. |
| `That org already has a GitHub App in LDE` | The org is already covered. Delete the extra app on GitHub. |
| `The GitHub App configuration is broken` | Fix the error the card shows, delete the extra app on GitHub, and start again. |
| GitHub says the redirect URL is invalid | Open LDE at its real URL. Set `LDE_ALLOWED_ORIGIN` to it when it is not `localhost`. |

### Optional: one enterprise-owned app

An enterprise owner creates the app in the enterprise's settings and adds it to LDE by hand
(Step 3). LDE tries it on every org that has no app of its own.

1. Open **github.com → your enterprise → Settings → GitHub Apps → New GitHub App**.
2. Follow steps 2–4 and 6–7 of [Create it by hand](#create-it-by-hand). For **Where can this
   GitHub App be installed?**, GitHub offers only **Only enterprise organizations**, which is
   what you want.
3. Do Step 2 on each org. Installing the app on the enterprise account itself does not give LDE
   access to any org's repos.

Enterprise-owned apps are limited to GitHub Enterprise Cloud. An org that leaves the enterprise
loses the install at once.

### Create it by hand

For the enterprise-owned app, or to control every field. Then do Step 3.

1. Open **github.com → your org → Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Set **GitHub App name** (for example `lde-reader-<org>`). Set **Homepage URL** to your LDE URL; GitHub requires a value but LDE does not use it.
3. Under **Webhook**, clear **Active**. LDE does not take webhooks.
4. Under **Repository permissions**, set:

   | Permission | Access | Used for |
   |---|---|---|
   | Contents | Read-only | Tree listing, manifest fetch, dependency graph SBOM and compare |
   | Metadata | Read-only | Org repo listing, default branch (GitHub adds this automatically) |

   Leave every other permission at **No access**. LDE asks for only these two when it mints a
   token, so a wider grant on the app is never used, but keep the app narrow anyway.
5. Under **Where can this GitHub App be installed?**, choose **Only on this account**.
6. Click **Create GitHub App**. Note the **App ID** at the top of the app's settings page.
7. Under **Private keys**, click **Generate a private key**. GitHub downloads a `.pem` file.
   It is the only copy, so keep it until Step 3 is done.

---

## Step 2 — Install the app on its org

1. Open the install page: click **Manage on GitHub** next to the app on LDE's Settings page, or
   open `https://github.com/apps/<app-slug>/installations/new`. The same page changes which
   repos an existing install can read.
2. Click **Install** next to the org. A private app lists only its owner. A member who is not an
   org owner sees **Request** instead, and GitHub asks the org's owners to approve it.
3. Choose **All repositories**, or **Only select repositories** to limit what LDE can read.
   Repos left out return 404, and LDE marks them `skipped`.
4. An org owner approves the install. Until then, LDE reports the org as
   `no GitHub App installed`.

For the enterprise-owned app, repeat for every org in the enterprise that LDE scans.

LDE picks up a new install within five minutes. A removed install is noticed on the next token
refresh, at most an hour later.

---

## Step 3 — Add a hand-made app to LDE

Only for an app created by hand. **Create app** (Step 1) already did this.

`owner` is the org, user or enterprise slug that owns the app. LDE tries an app first on the
org with that name. Each App ID and each owner can appear only once; a duplicate, or any
malformed entry, is an error for every org.

### Local

Move the key out of `~/Downloads` and lock it down. LDE refuses a key file that any other user
can read.

```bash
mkdir -p ~/.lde
mv ~/Downloads/<app-name>.*.private-key.pem ~/.lde/github-app-<app-id>.pem
chmod 600 ~/.lde/github-app-<app-id>.pem
```

Append the app to `github_apps` in `.settings.json`. See `.settings.json.example`.

```json
{
  "github_apps": [
    {"owner": "acme", "app_id": "123456", "private_key_path": "~/.lde/github-app-123456.pem"},
    {"owner": "my-enterprise", "app_id": "234567", "private_key_path": "~/.lde/github-app-234567.pem"}
  ]
}
```

`github_apps` is file-only: `PUT /api/settings` rejects it, and `GET /api/settings` never
returns it. `LDE_GITHUB_APPS` (a JSON list) overrides it. The older single-app keys
`github_app_id` and `github_app_private_key_path` still work, as one app LDE tries on every org.

### AWS

`lde/github-app` holds `{"apps": [{"owner", "app_id", "private_key"}, ...]}`. Read the current
value, append the app, and write it back. `--rawfile` keeps the key's newlines intact.

```bash
aws secretsmanager get-secret-value --secret-id lde/github-app --region us-east-1 \
    --query SecretString --output text > "$TMPDIR/lde-github-app.json"
# A REPLACE_ME (or the older single-app object) value: start from an empty list instead.
jq -e '.apps' "$TMPDIR/lde-github-app.json" >/dev/null 2>&1 || echo '{"apps": []}' > "$TMPDIR/lde-github-app.json"
jq --arg owner my-enterprise --arg id 234567 --rawfile key ~/.lde/github-app-234567.pem \
    '.apps += [{owner: $owner, app_id: $id, private_key: $key}]' "$TMPDIR/lde-github-app.json" \
  | tr -d '\n' \
  | aws secretsmanager put-secret-value \
      --secret-id lde/github-app \
      --secret-string file:///dev/stdin \
      --region us-east-1
rm -f "$TMPDIR/lde-github-app.json"
```

The temporary file holds every app's private key: keep it in `$TMPDIR` and delete it.
Starting from an empty list drops an older single-app object; add that app back as an entry
too if it is still in use. `tr -d '\n'` strips only the newline `jq` adds after the object.

Confirm the secret's shape without printing it:

```bash
python3 scripts/check_aws.py verify
# OK   lde/github-app: 2 app(s): acme (123456), my-enterprise (234567)
```

Once the secret is written, delete the downloaded `.pem` unless you also run LDE locally.

---

## Step 4 — Confirm

LDE reads Secrets Manager within a minute. No restart is needed.

```bash
curl -s -u admin:password http://localhost:8002/api/gh-status | python3 -m json.tool
```

Expect `"mode": "app"`, `"ok": true` for every entry in `apps`, and `"via": "app"` with
`"ok": true` for every org. **Settings → Test GitHub Apps** shows the same thing.

| Message | Fix |
|---|---|
| `GitHub rejected the JWT for app <id> (HTTP 401)` | The key does not belong to that App ID, or it was deleted on GitHub. |
| `no GitHub App installed` | Create an app for that org (Step 1), or do Step 2, or wait for the org owner to approve. |
| `does not have Contents: Read and Metadata: Read` | Fix the app's permissions (Step 1, by hand, step 4). Orgs must accept a permission change before it applies. |
| `private key file is readable by other users` | `chmod 600` the key file. |
| `same GitHub App ID is configured more than once` / `same owner` | Remove the duplicate entry. |
| `needs the cryptography package` | `pip install -r requirements.txt` |

---

## Migrate from PATs

1. Check `/api/gh-status` or the Settings card: every org with `"via": "pat"` still uses a PAT,
   and `notice` lists them.
2. For each, click **Create app for &lt;org&gt;** and install the app (Steps 1–2). Or install the
   enterprise-owned app on it.
3. Once the org shows `app`, remove its PAT in Settings (locally), or set `lde/github-pat` back
   to `REPLACE_ME` (AWS) after the last one.

A misconfigured app (for example a malformed `github_apps` entry) is an error for every org.
LDE does not quietly fall back to PATs when the app config is broken.

---

## Remove an app

1. Delete its entry from `github_apps` in `.settings.json` and its key file (locally), or from
   the `apps` list in `lde/github-app` (AWS, with the read-edit-write commands in Step 3).
2. Delete the app on GitHub: the app's settings page → **Advanced** → **Delete GitHub App**.

---

## Rotate a private key

Each app has its own key; rotate them one at a time.

1. On the app's settings page, click **Generate a private key**. Both keys work until you delete one.
2. Replace the key file (locally, keep the same path and mode 0600) or the app's `private_key`
   in `lde/github-app` (AWS, Step 3).
3. Confirm with `/api/gh-status` (Step 4).
4. Delete the old key on the app's settings page.

Installation tokens already issued stay valid until they expire (at most an hour). Deleting a
key does not revoke them.

---

## GitHub API rate limits

Each installation has its own limit: at least 5,000 requests per hour, rising with the org's
repos and users up to 12,500 (15,000 on GitHub Enterprise Cloud). The limit belongs to the
org's installation, not to a person, so scans of different orgs do not share a budget and do
not use up anyone's personal PAT quota. LDE backs off and retries when GitHub returns 429 or a
403 with `X-RateLimit-Remaining: 0`.

---

## Cost

| Resource | Monthly cost | Notes |
|---|---|---|
| `lde/github-app` secret | $0.40 + $0.05 per 10,000 API calls | LDE caches each secret for 60 s |
| GitHub App | $0 | Apps are free on every GitHub plan |

---

## Security notes

- **One-click setup.** `POST /api/gh-app/manifest` builds the app's callback URL from the
  request's `Origin` (localhost or `LDE_ALLOWED_ORIGIN`), never from the `Host` header. The
  callback accepts only a single-use, one-hour `state` LDE issued. It only ever adds an app: it
  is refused when the owner GitHub reports already has one, or when that owner differs from the
  org setup was started for, so a forged callback cannot replace or redirect an org's app. The
  key goes from GitHub straight to the server and is written with `O_EXCL | O_NOFOLLOW` and
  mode 0600. On AWS the task role can write `lde/github-app` and no other secret.
- **Read-only.** Every installation token is minted with only `contents:read` and
  `metadata:read`, whatever the app is granted. LDE makes only GET calls with it.
- **Key handling.** Each key is read from Secrets Manager or from a 0600 file whose path is
  canonicalized before any check. It is never accepted over HTTP, never returned by
  `GET /api/settings`, never written to `.settings.json`, and never logged.
- **Tokens.** App JWTs live nine minutes and installation tokens one hour. Both are held in
  memory only.
- **Network.** Calls go only to `https://api.github.com`, with explicit timeouts. Redirects are
  refused so a bearer token cannot follow one to another host.
- **Fail closed.** An org that neither the app nor a PAT covers is an error, never an
  unauthenticated request. A broken app config is an error, not a silent PAT fallback.
