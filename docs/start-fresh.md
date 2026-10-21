# start_fresh.py

A Python CLI that starts the local stack from a clean slate. Starts Docker and Dependency-Track, permanently deletes LDE's database and `runs/` (pass `--backup` to move them to a timestamped backup folder instead), deletes every Dependency-Track project, then starts `server.py` and checks it.

Use it when you want an empty local LDE: no old runs in the UI and no old components in package search. For reclaiming disk space, use `scripts/cleanup.sh` instead.

Local only. Do not run it against a production Dependency-Track.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| `python3` | 3.9+ | Stdlib only; no pip install needed |
| Docker Desktop | 4.x+ | Started automatically on macOS if not running |
| `docker compose` | v2 | Uses BuildKit, which reads `Dockerfile.dtrack.dockerignore` |
| `lsof`, `ps` | system | Used to identify the process on the LDE port |
| `~/.lde/dtrack-admin.txt` or `~/.lde/dtrack-admin.local.txt` | — | Local Dependency-Track admin login: username on line 1, password on line 2. Written by `scripts/bootstrap_dtrack.py`. Not needed with `--keep-data` or `--keep-dtrack`. A factory volume has no matching file yet; `start_fresh.py` prints the bootstrap command instead of treating that as a failed login. |
| `.settings.json` | — | Created from `.settings.json.example` if missing. `dtrack_api_key` is copied from `~/.lde/dtrack-api-key.txt` when the settings key is empty (after `bootstrap_dtrack.py`, or by `start_fresh.py`). |

## Usage

```
python3 scripts/start_fresh.py [options]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--keep-data` | | | Restart only. Keep LDE data and Dependency-Track projects |
| `--keep-dtrack` | | | Clear LDE data but keep Dependency-Track projects |
| `--backup` | | | Move cleared LDE data to `~/.lde/backups/lde-local-<UTC timestamp>/` instead of deleting it |
| `--yes` | `-y` | | Skip the confirmation prompt. Required when stdin is not a terminal |
| `--port <n>` | | `8002` | LDE port to stop and start on |
| `--dtrack-url <url>` | | `http://127.0.0.1:8081` | Dependency-Track **API** URL (`dtrack_url`, not `dtrack_ui_url`) |
| `--dtrack-password-file <path>` | | `~/.lde/dtrack-admin.txt` | Admin login file |
| `--help` | `-h` | | Print usage and exit |

### What it does

1. **Preflight (read-only).** Checks Docker is available (or can be started on macOS), probes Dependency-Track with `GET /api/version` if it is already up, checks who owns the LDE port, and counts what it will clear. If the API is already up it classifies admin state (factory vs matching password file vs mismatch), logs in only on a match, and lists projects for the summary. It does not start Docker Desktop or run `docker compose up`, and it never rotates the admin password.
2. **Confirm.** Prints the summary and asks `Continue? [y/N]`. A declined prompt (or a missing `--yes` with no terminal) exits with nothing changed.
3. **Start Dependency-Track.** Starts Docker Desktop if needed, then `docker compose up -d dtrack-apiserver dtrack-frontend`, and waits for `/api/version`. Classifies admin state and lists projects here if the API was down during preflight. A factory instance stops here with the bootstrap command; nothing else is changed.
4. **Stop LDE.** Sends SIGTERM to the process on the port, only if it is this repository's `server.py`.
5. **Clear LDE data.** Permanently deletes `depexplorer.db`, `depexplorer.db-shm`, `depexplorer.db-wal` and `runs/` from `LDE_DATA_DIR` (or the repository root). It deletes only those names, never through a symlink. With `--backup`, it moves them to `~/.lde/backups/lde-local-<UTC timestamp>/` (mode `0700`) instead.
6. **Delete Dependency-Track projects.** Deletes every project, then re-lists and fails if any remain.
7. **Start LDE.** If `.settings.json` has an empty `dtrack_api_key` and `~/.lde/dtrack-api-key.txt` exists, copies the key in (does not overwrite a non-empty settings key). Runs `python3 server.py --port <n>` in the foreground, then checks `/api/runs`, `/api/dtrack-status` and `/api/gh-status`. Press Ctrl-C to stop the server.

Any failure in steps 1–2 exits with nothing changed. After you confirm, a later failure (login after a first-time compose start, a delete error) can leave Dependency-Track running.

The script keeps the Dependency-Track volume, settings, teams, API keys, admin login and vulnerability mirror. To wipe those too, run `docker compose down -v` and follow the README quick start from step 1.

## Examples

**Start fresh with a prompt:**

```bash
python3 scripts/start_fresh.py
```

```
This will:
  - stop LDE on port 8002 (PID 29323)
  - permanently delete LDE data in /path/to/repo (4 run(s), 17 repo result(s))
  - delete 8 Dependency-Track project(s): example-org/example-service, ...
  - start LDE on http://127.0.0.1:8002

Continue? [y/N]
```

**Start fresh without a prompt:**

```bash
python3 scripts/start_fresh.py --yes
```

**Restart only, keeping all data:**

```bash
python3 scripts/start_fresh.py --keep-data
```

**Clear LDE runs but keep Dependency-Track projects** (package search still finds old components):

```bash
python3 scripts/start_fresh.py --keep-dtrack
```

**Restore LDE data backed up with `--backup`.** Stop the server, then move the files back. Data cleared without `--backup` cannot be restored:

```bash
mv ~/.lde/backups/lde-local-<timestamp>/* .
python3 server.py
```

Deleted Dependency-Track projects cannot be restored this way. Re-ingest from LDE instead.

### Edge cases

**Another process holds the port.** The script refuses to stop it:

```
start_fresh: port 8002 is held by PID 4242 (python3 -m http.server 8002), which is not this repo's server.py. Stop it yourself or pass --port.
```

**Factory / never bootstrapped.** `admin`/`admin` still returns `FORCE_PASSWORD_CHANGE`. The script stops before changing anything and prints the bootstrap command. It does not rotate the admin password and does not overwrite `~/.lde/dtrack-admin.txt`:

```
start_fresh: Dependency-Track is factory / never bootstrapped (admin/admin still requires FORCE_PASSWORD_CHANGE). Nothing was changed. This script does not rotate the admin password. Run:
  DTRACK_ADMIN_PASSWORD=admin python3 scripts/bootstrap_dtrack.py --password-out ~/.lde/dtrack-admin.local.txt --no-aws
Then re-run:
  python3 scripts/start_fresh.py --yes --dtrack-password-file ~/.lde/dtrack-admin.local.txt
```

If `~/.lde/dtrack-admin.txt` exists, copy it first (`cp -np ~/.lde/dtrack-admin.txt ~/.lde/dtrack-admin.other.txt`); it may belong to another instance. `bootstrap_dtrack.py` writes the API key to `~/.lde/dtrack-api-key.txt` and into `.settings.json` as `dtrack_api_key`.

Dependency-Track UI (`http://127.0.0.1:8080`) username is `admin`. Copy the new password to the clipboard without printing it:

```bash
sed -n 2p ~/.lde/dtrack-admin.local.txt | tr -d '\n' | pbcopy
```

**Admin login does not match a bootstrapped instance.** The password file is wrong, and factory `admin`/`admin` no longer works. The script stops before changing anything:

```
start_fresh: Dependency-Track admin login failed (HTTP 401: INVALID_CREDENTIALS). The password file does not match this instance (already bootstrapped, not factory). Nothing was changed. See docs/start-fresh.md#recover-the-dependency-track-admin-password
```

Run `python3 scripts/start_fresh.py --keep-dtrack` to clear LDE only, or recover the password (below). This is not "password was already changed" — that message is gone; a stale password against a factory volume is the factory case above.

**GitHub token rejected.** Reported as a warning; the script still succeeds:

```
[start_fresh] WARN GitHub: PAT is configured but authentication failed (HTTP 401). ... github_sbom runs will fail.
```

Set a valid token per org under `github_pats` in `.settings.json`.

## Recover the Dependency-Track admin password

Use this when `~/.lde/dtrack-admin.txt` no longer matches the local instance and nobody knows the password.

A common cause: `scripts/bootstrap_dtrack.py` writes `~/.lde/dtrack-admin.txt` by default, so running it against another instance (for example AWS) overwrites the local password. Pass `--password-out` when bootstrapping any other instance.

Check the audit log first. It records every login and password change:

```bash
docker compose exec dtrack-apiserver \
  cat /data/.dependency-track/dependency-track-audit.log
```

The Compose project name is the checkout directory (`lde` for a clone in `lde/`). `scripts/reset_dtrack_admin.py` uses `<project>-dtrack-apiserver-1` and `<project>_dtrack_data`. In the volume-backup commands below, set `PROJECT=$(basename "$PWD")` if this checkout is not named `lde`.

`scripts/reset_dtrack_admin.py` runs steps 1–6 below. It previews the plan and asks for confirmation before it changes anything. On a failed login it leaves the password file alone and prints the restore command. Run it yourself, because it changes a credential:

```bash
python3 scripts/reset_dtrack_admin.py
```

It skips the volume backup in step 2 unless you pass `--backup`. Without one, a failed reset cannot be rolled back.

The reset replaces the admin row's hash in the embedded H2 database. Dependency-Track 4.14 (Alpine 3.9) stores `bcrypt(lowercase hex SHA-512(password))` at cost 14, with a `$2a$` prefix. A plain bcrypt of the password will not work.

1. Save the current password file if it may belong to another instance:

    ```bash
    cp -np ~/.lde/dtrack-admin.txt ~/.lde/dtrack-admin.other.txt
    ```

2. Stop the API server and back up the volume:

    ```bash
    docker compose stop dtrack-apiserver
    mkdir -p -m 700 ~/.lde/backups
    docker run --rm --entrypoint tar \
      -v lde_dtrack_data:/data:ro -v ~/.lde/backups:/backup \
      library-dependency-explorer/dtrack-apiserver:local \
      cf /backup/dtrack_data-$(date +%F).tar -C /data .
    chmod 600 ~/.lde/backups/dtrack_data-*.tar
    ```

3. Extract the H2 jar that Dependency-Track ships:

    ```bash
    W=$(mktemp -d)
    docker compose cp dtrack-apiserver:/opt/owasp/dependency-track/dependency-track-apiserver.jar "$W/"
    unzip -oqj "$W/dependency-track-apiserver.jar" 'WEB-INF/lib/h2-*.jar' -d "$W/lib"
    ```

4. Generate a password and its hash. The password goes through files and stdin, never the command line:

    ```bash
    (umask 077; python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("admin");print("".join(secrets.choice(a) for _ in range(32)))' > "$W/new-admin.txt")
    HASH=$(python3 -c 'import hashlib,sys;print(hashlib.sha512(open(sys.argv[1]).read().split("\n")[1].encode()).hexdigest())' "$W/new-admin.txt" \
      | htpasswd -niB -C 14 admin | cut -d: -f2 | sed 's/^\$2y\$/$2a$/')
    printf "UPDATE MANAGEDUSER SET PASSWORD='%s', FORCE_PASSWORD_CHANGE=FALSE, LAST_PASSWORD_CHANGE=CURRENT_TIMESTAMP WHERE USERNAME='admin';\n" "$HASH" > "$W/reset.sql"
    chmod 644 "$W/reset.sql"
    ```

5. Apply it and restart:

    ```bash
    docker run --rm --entrypoint java \
      -v lde_dtrack_data:/data -v "$W/lib":/h2:ro -v "$W/reset.sql":/reset.sql:ro \
      library-dependency-explorer/dtrack-apiserver:local \
      -cp "/h2/$(ls "$W/lib")" org.h2.tools.RunScript \
      -url 'jdbc:h2:/data/.dependency-track/db' -user sa -password '' -script /reset.sql
    rm "$W/reset.sql"
    docker compose start dtrack-apiserver
    ```

6. Confirm the login works, then save the password:

    ```bash
    python3 - "$W/new-admin.txt" <<'EOF'
    import sys, urllib.request, urllib.parse
    u, p = open(sys.argv[1]).read().split('\n')[:2]
    req = urllib.request.Request('http://127.0.0.1:8081/api/v1/user/login',
        data=urllib.parse.urlencode({'username': u, 'password': p}).encode(), method='POST')
    urllib.request.urlopen(req, timeout=15); print('login: OK')
    EOF
    mv "$W/new-admin.txt" ~/.lde/dtrack-admin.txt
    ```

If the login fails, restore the backup from step 2 into the volume before trying again.

## GitHub API rate limits

The script makes one GitHub API call per run, through LDE's `/api/gh-status` check. It does not count toward any practical limit.

## Security notes

- The admin password is read only from `--dtrack-password-file`. It is never printed, logged or passed on a command line.
- The admin session token is held in memory only and never printed. Error output shows Dependency-Track reason codes (`INVALID_CREDENTIALS`), never response bodies from a successful login.
- `dtrack_api_key` is copied from `~/.lde/dtrack-api-key.txt` into `.settings.json` only when the settings key is empty. A non-empty settings key is left alone. The key is never printed.
- Backups are opt-in (`--backup`) and go to `~/.lde/backups/` with directory mode `0700`. They hold your run history; delete them when no longer needed.
- The script stops a process only after confirming it is this repository's `server.py`.
- Destructive steps run only after preflight passes and you confirm, or pass `--yes`. Starting Docker Desktop and `docker compose up` wait for that confirmation too.
