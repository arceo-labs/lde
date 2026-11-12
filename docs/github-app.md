# GitHub orgs and GitHub App authentication

LDE keeps one list of the GitHub orgs it reads: the **org map**. Each org names exactly one way
to authenticate:

| `auth` | Credential | Set up with |
|---|---|---|
| `app` | The org's own private GitHub App | **Settings → Create app for &lt;org&gt;**, one click |
| `enterprise` | The one enterprise-owned app (optional) | By hand, by an enterprise owner ([below](#optional-the-enterprise-app)) |
| `pat` | A fine-grained PAT for that org. **Deprecated.** | Settings, per org |
| `none` | Nothing yet. GitHub calls to the org fail. | Settings → **Add org** |

Each org also has `scan`. Runs that name no orgs scan every org with `scan: true`. This replaces
`default_orgs`.

There is no catch-all entry and no fallback. An org that is missing from the map, or whose own
credential fails, is an error. LDE never tries another app or a PAT instead.

For an app org, LDE trades the app's key for a one-hour installation token and uses that token
for every GitHub call to the org.

```
 org map: lde/github secret (AWS) or "github" in .settings.json (local)
   orgs:  {acme: {auth: app, app_id, key}, globex: {auth: pat, token}, initech: {auth: enterprise}}
   enterprise_app: {enterprise, app_id, key}
            │  org X → X's entry only
            ▼
   backend/gh_config.py ── app / enterprise ──► backend/gh_app.py ── app JWT (RS256, 9 min) ──┐
            │                                         │                                       │
            │ pat                                     │  GET  /orgs/{org}/installation    ◄───┤ api.github.com
            │                                         │  POST /app/installations/{id}/access_tokens
            │                                         │       permissions: contents:read, metadata:read
            │                                         ▼
            │                     installation token (1 h, in memory, refreshed 5 min early)
            ▼                                         │
   backend/github_client.py ◄─────────────────────────┘ trees, contents, SBOM, dependency compare
```

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.11+ | Same as the rest of LDE |
| `cryptography` | 46.0.3 | Signs the app JWT. `pip install -r requirements.txt` installs it; the Docker image already has it. **Create app** refuses to start without it. |
| GitHub org owner | — | Creates the org's app and installs it. Members who are not owners can request the install. |
| `LDE_ALLOWED_ORIGIN` | — | Any deployment not on `localhost`: the exact URL you open LDE at. The app's callback URL is built from it. Terraform sets it on AWS. |
| `jq` | 1.6+ | AWS only, for the enterprise app or hand edits of `lde/github` |

---

## Where the org map lives

| Deployment | Stored in | App keys |
|---|---|---|
| Local | `"github"` in `.settings.json` | Files: `private_key_path`, mode 0600. An inline `private_key` is refused. |
| AWS (`LDE_SECRETS_SOURCE=aws`) | The `lde/github` secret | Inline: `private_key`. A `private_key_path` is refused. |

Settings writes the map in both places. On AWS the ECS task role may write `lde/github` and no
other secret.

A secret holds at most 64 KB, which fits about 35 orgs with their own app. **Create app** is
refused once `lde/github` is close to full; past that, use the enterprise app.

Each save reads `lde/github`, changes one org and writes the whole map back. While a deploy
runs, the old and new tasks both serve requests, and two saves at once keep only the later
one. Don't change orgs during a deploy; afterwards, check that every change is still there.

```json
{
  "github": {
    "orgs": {
      "acme":    {"auth": "app", "scan": true, "app_id": "123456",
                  "private_key_path": "~/.lde/github-app-123456.pem"},
      "globex":  {"auth": "pat", "scan": true, "token": "github_pat_..."},
      "initech": {"auth": "enterprise", "scan": false},
      "hooli":   {"auth": "none", "scan": false}
    },
    "enterprise_app": {"enterprise": "my-enterprise", "app_id": "234567",
                       "private_key_path": "~/.lde/github-enterprise-app.pem"}
  }
}
```

Org names are lower-cased. `scan` defaults to `true`. The map is validated strictly. Each of the
following is an error for **every** org, so a typo cannot quietly skip an org:
- an unknown field;
- a `"*"` org;
- a missing token or App ID;
- `auth: enterprise` without an `enterprise_app`.

No environment variable overrides the map: `LDE_GITHUB`, `LDE_GITHUB_PATS` and
`LDE_DEFAULT_ORGS` are ignored, with a notice in Settings. `GET /api/settings` never returns the
map, and `PUT /api/settings` refuses it: use Settings or [`/api/github/orgs`](api.md).

### Moving from the old settings

The old keys are still read until the first save: `default_orgs` and `github_pats` (on AWS, the
`lde/github-pat` secret). While no map is stored, LDE derives one from them in memory:
- every org with a PAT becomes `auth: pat`;
- every other org in `default_orgs` becomes `auth: none`;
- `scan` is on for the orgs that were in `default_orgs`.

The Settings card shows a notice while this is happening.

Any change in Settings, or a new app, then writes the map. Locally, LDE writes it to `"github"`
and removes the old keys from `.settings.json`. On AWS, it writes it to `lde/github`. Then set
`lde/github-pat` back to `REPLACE_ME`; `check_aws.py verify` warns until you do.

The `"*"` PAT, a token used for any org without its own entry, is **dropped**. It existed for
classic PATs, which can reach every org their user can. Add each org that relied on it.

---

## Step 1 — Create an app for each org

### Create it from LDE

1. Open LDE at the URL you normally use (`http://localhost:8002`, or your `lde_domain`), then go
   to **Settings**. The **GitHub auth** card has one row per org.
2. On an org's row, click **Create app for &lt;org&gt;**. For an org not in the table, either:
   - **Add org** it first, or
   - open **Create a GitHub App for an org not listed yet**, enter the org (blank = your
     personal account) and an optional name, then click **Create GitHub App on GitHub**.
3. GitHub shows the app's name and its two read-only permissions. Click
   **Create GitHub App for &lt;org&gt;**. You must be an owner of that org.
4. GitHub sends you back to LDE, which sets the org's entry to `auth: app` with the new App ID.
   An existing `scan` flag is kept; a new org gets `scan: true`.
   - Locally, the key goes to a new file `~/.lde/github-app-<id>.pem` (mode 0600), and the
     entry gets its `private_key_path`.
   - On AWS, the key goes inline into the entry in `lde/github`.

   The key never passes through your browser. LDE throws away the client secret and webhook
   secret GitHub also returns. The org LDE records is the owner GitHub reports for the new app.
5. LDE then sends you to the app's install page: continue with Step 2.

LDE never replaces an app. It refuses to create a new app in two cases:
- the org already has `auth: app`;
- the org map is broken.

An org on a PAT, `enterprise` or `none` switches to its new app.

| Back on Settings with | Fix |
|---|---|
| `setup link was unknown, already used or expired` | Start again from Settings. Each link works once, for an hour, and does not survive an LDE restart. |
| `GitHub did not hand over the new app` | Start again. GitHub's one-time code expires after an hour. Delete the half-made app on GitHub if it exists. |
| `could not store the new app's private key` | Check the server log. On AWS the task role needs `secretsmanager:PutSecretValue` on `lde/github` (`terraform apply`). Delete the unused app on GitHub, then start again. |
| `That org already has its own GitHub App` | Delete the extra app on GitHub. |
| `The GitHub config is broken` | Fix the error the card shows, delete the extra app on GitHub, and start again. |
| GitHub says the redirect URL is invalid | Open LDE at its real URL. Set `LDE_ALLOWED_ORIGIN` to it when it is not `localhost`. |

### Optional: the enterprise app

Use this for several orgs in one GitHub Enterprise Cloud enterprise, as an alternative to one
app per org. An enterprise owner creates one app in the enterprise's settings. Then:
- add it to LDE by hand as `enterprise_app` (Step 3);
- set each org it covers to `auth: enterprise` in Settings.

LDE supports one enterprise app. GitHub's one-click flow cannot create enterprise-owned apps.

1. Open **github.com → your enterprise → Settings → GitHub Apps → New GitHub App**.
2. Follow steps 2–4 and 6–7 of [Create it by hand](#create-it-by-hand). For **Where can this
   GitHub App be installed?**, GitHub offers only **Only enterprise organizations**, which is
   what you want.
3. Do Step 2 on each org. Installing the app on the enterprise account itself does not give LDE
   access to any org's repos.

Enterprise-owned apps are limited to GitHub Enterprise Cloud. An org that leaves the enterprise
loses the install at once.

### Create it by hand

Use this for the enterprise app, or to control every field. Then do Step 3.

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

1. Open the install page: click **Manage on GitHub** on the org's row in Settings, or open
   `https://github.com/apps/<app-slug>/installations/new`. The same page changes which repos an
   existing install can read.
2. Click **Install** next to the org. A private app lists only its owner. A member who is not an
   org owner sees **Request** instead, and GitHub asks the org's owners to approve it.
3. Choose **All repositories**, or **Only select repositories** to limit what LDE can read.
   Repos left out return 404, and LDE marks them `skipped`.
4. An org owner approves the install. Until then, LDE reports the org as `not installed`.

For the enterprise app, repeat for every org set to `auth: enterprise`.

LDE picks up a new install within five minutes. A removed install is noticed on the next token
refresh, at most an hour later.

---

## Step 3 — Add a hand-made app to LDE

Only for an app created by hand. **Create app** (Step 1) already did this. App IDs and keys are
never accepted over HTTP, so this is a file or secret edit.

### Local

Move the key out of `~/Downloads` and lock it down. LDE refuses a key file that any other user
can read.

```bash
mkdir -p ~/.lde
mv ~/Downloads/<app-name>.*.private-key.pem ~/.lde/github-app-<app-id>.pem
chmod 600 ~/.lde/github-app-<app-id>.pem
```

Edit `"github"` in `.settings.json`. If it is not there yet, save any org in Settings once so
LDE moves the old keys over. Then add one of:
- an org entry `{"auth": "app", "scan": true, "app_id": "<id>", "private_key_path": "<pem>"}`;
- or the `enterprise_app` object shown in [Where the org map lives](#where-the-org-map-lives).

Restart nothing: LDE reads the file on every request.

### AWS

Read the current value, add the app, and write it back. `--rawfile` keeps the key's newlines
intact. This adds the enterprise app; for an org's own app use
`.orgs[$org] = {auth: "app", scan: true, app_id: $id, private_key: $key}`.

```bash
aws secretsmanager get-secret-value --secret-id lde/github --region us-east-1 \
    --query SecretString --output text > "$TMPDIR/lde-github.json"
# REPLACE_ME: save any org in Settings first, so LDE writes the map (with the old secrets moved in).
jq -e '.orgs' "$TMPDIR/lde-github.json" >/dev/null || echo 'Save an org in Settings first'
jq --arg ent my-enterprise --arg id 234567 --rawfile key ~/.lde/github-enterprise-app.pem \
    '.enterprise_app = {enterprise: $ent, app_id: $id, private_key: $key}' "$TMPDIR/lde-github.json" \
  | tr -d '\n' \
  | aws secretsmanager put-secret-value \
      --secret-id lde/github \
      --secret-string file:///dev/stdin \
      --region us-east-1
rm -f "$TMPDIR/lde-github.json"
```

The temporary file holds every app key and PAT in the map: keep it in `$TMPDIR` and delete it.
`tr -d '\n'` strips only the newline `jq` adds after the object.

Confirm the secret's shape without printing it:

```bash
python3 scripts/check_aws.py verify
# OK   lde/github: 3 org(s) (1 app, 2 enterprise), 3 scanned; enterprise app for my-enterprise
```

Once the secret is written, delete the downloaded `.pem` unless you also run LDE locally.

---

## Step 4 — Confirm

LDE reads Secrets Manager within a minute. No restart is needed.

```bash
curl -s -u admin:password http://localhost:8002/api/gh-status | python3 -m json.tool
```

Expect `"logged_in": true`, `"config_error": ""`, and `"ok": true` for every org in `orgs` that
is not `none`. **Settings → Check again** shows the same thing.

| Message | Fix |
|---|---|
| `GitHub rejected the JWT for app <id> (HTTP 401)` | The key does not belong to that App ID, or it was deleted on GitHub. |
| `<app> is not installed on <org>` | Do Step 2, or wait for the org owner to approve. |
| `Org '<org>' is not set up in LDE` | Add the org in Settings and create its app. |
| `has no GitHub credential yet` | The org is `none`: click **Create app for &lt;org&gt;**. |
| `does not have Contents: Read and Metadata: Read` | Fix the app's permissions (Step 1, by hand, step 4). Orgs must accept a permission change before it applies. |
| `private key file is readable by other users` | `chmod 600` the key file. |
| `The "*" org is no longer supported` | Replace the `*` entry with one entry per org. |
| `Could not read the lde/github secret` | Check the task role can read `lde/github` (`terraform apply`). GitHub calls fail meanwhile; LDE does not fall back to the old secrets. |
| `needs the cryptography package` | `pip install -r requirements.txt` |

---

## Migrate from PATs

1. Check the Settings card or `/api/gh-status`. Every org with `auth: pat` still uses a PAT, and
   `notice` lists them.
2. For each, click **Create app for &lt;org&gt;** and install the app (Steps 1–2). Creating the
   app switches the org to it and drops its PAT. Alternatively, set the org to `enterprise`.

---

## Remove an org or an app

1. In Settings, click **Remove** on the org's row (twice to confirm). Or switch its auth to
   `none`. Locally, LDE leaves the org's key file in `~/.lde`; delete it yourself.
2. Delete the app on GitHub: the app's settings page → **Advanced** → **Delete GitHub App**.

To remove the enterprise app, set its orgs to another auth, then delete `enterprise_app` from
the map by hand.

---

## Rotate a private key

Each app has its own key; rotate them one at a time.

1. On the app's settings page, click **Generate a private key**. Both keys work until you delete one.
2. Replace the key:
   - Locally, overwrite the key file, keeping the same path and mode 0600.
   - On AWS, replace the entry's `private_key` in `lde/github`, using the read-edit-write
     commands in Step 3.
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
| `lde/github` secret | $0.40 + $0.05 per 10,000 API calls | LDE caches each secret for 60 s |
| `lde/github-pat` | $0.40 | Old PAT secret, kept for migration |
| GitHub App | $0 | Apps are free on every GitHub plan |

---

## Security notes

- **One credential per org.** Each org's entry names its only credential. LDE never tries
  another org's app, the enterprise app, or a PAT in its place, and there is no catch-all `*`
  token.
- **One-click setup.**
  - `POST /api/gh-app/manifest` builds the app's callback URL from the request's `Origin`
    (localhost or `LDE_ALLOWED_ORIGIN`), never from the `Host` header.
  - The callback accepts only a single-use, one-hour `state` that LDE issued.
  - Setup is refused when the owner GitHub reports already has its own app, or differs from the
    org that setup was started for. A forged callback therefore cannot replace or redirect an
    org's app.
  - The key goes from GitHub straight to the server. Locally it is written with
    `O_EXCL | O_NOFOLLOW` and mode 0600. On AWS the task role can write `lde/github` and no
    other secret.
- **Org changes over HTTP.**
  - `PUT /api/github/orgs/<org>` accepts only `auth`, `scan` and `token`. It never accepts an
    App ID, a key or a key path.
  - `auth: app` is accepted only for an org that already has its app.
  - PATs are write-only: `/api/gh-status` shows the first four characters.
  - `PUT` and `DELETE` need Basic Auth (when configured), a JSON `Content-Type` and an allowed
    `Origin`.
- **Read-only.** Every installation token is minted with only `contents:read` and
  `metadata:read`, whatever the app is granted. LDE makes only GET calls with it.
- **Key handling.**
  - Each key is read from Secrets Manager or from a 0600 file whose path is canonicalized
    before any check.
  - Keys are never accepted over HTTP, never returned by any endpoint, and never logged.
  - Locally a key is never written to `.settings.json`.
- **Tokens.** App JWTs live nine minutes and installation tokens one hour. Both are held in
  memory only.
- **Network.** Calls go only to `https://api.github.com`, with explicit timeouts. Redirects are
  refused so a bearer token cannot follow one to another host.
- **Fail closed.**
  - An org that is missing, `none`, or whose credential fails is an error, never an
    unauthenticated request.
  - A broken or unreadable org map is an error for every org, never a fallback to the old keys.
