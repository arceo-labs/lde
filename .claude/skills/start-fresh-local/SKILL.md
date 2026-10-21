---
name: start-fresh-local
description: Start, restart or reset the local LDE stack (server.py + Dependency-Track) through scripts/start_fresh.py. Use when asked to run or spin up the app locally, to clear local runs or Dependency-Track projects, or when the local Dependency-Track admin login fails.
---

# start-fresh-local

`scripts/start_fresh.py` owns the mechanics: Docker, the Dependency-Track services, port ownership, backups, project deletion and the startup checks. `--help` lists its flags. This skill owns the judgement around it.

## Steps

1. **Pick the mode** from the request.

    | Request | Flags |
    |---|---|
    | run, spin up, restart | `--keep-data` |
    | clear LDE runs, keep package-search data | `--keep-dtrack` |
    | start fresh, clean slate, reset everything | none |

    When the wording leaves it open, pick `--keep-data`: clearing is the user's call.

2. **Preview.** Run the script with the chosen flags and without `--yes`. With no terminal attached, it is read-only: it probes Dependency-Track if it is already up, checks the port and the admin login, prints a `This will:` plan, and exits before starting Docker, compose, or LDE. If LDE is up, also read `started_at` from `curl -s localhost:8002/api/runs`. Runs or projects you did not create in this conversation are the user's recent work. Done when you can show the user the plan, naming any recent work it would clear.

3. **Get the go-ahead** for that plan, then rerun with `--yes`. A go-ahead covers the plan it answered. A later clear gets its own preview and go-ahead. `--keep-data` changes no data, so it goes straight to `--yes`.

4. **Run it in the background** (`run_in_background`), because the script stays attached as the server. Done when the output shows `LDE is running`.
    - Relay any `FAIL` line verbatim.
    - Report `WARN GitHub` as "`github_pats` in `.settings.json` is rejected; `github_sbom` runs will fail".
    - The server ends with this session. For a long-lived server, give the user the command to run in their own terminal.

## When the preview stops

**`factory / never bootstrapped`.** `admin`/`admin` still requires `FORCE_PASSWORD_CHANGE`. Nothing has changed. Show the user the printed `bootstrap_dtrack.py` command (it uses `--password-out ~/.lde/dtrack-admin.local.txt` so `~/.lde/dtrack-admin.txt` is not overwritten). They run it. Then rerun `start_fresh.py --yes --dtrack-password-file ~/.lde/dtrack-admin.local.txt`. Auto mode still blocks the agent from rotating the admin password.

**Password file does not match (already bootstrapped, not factory).** Nothing has changed yet.
1. Read the audit log: `docker compose exec dtrack-apiserver cat /data/.dependency-track/dependency-track-audit.log`. It records every login and password change.
2. Compare it with the file's modification time. A file rewritten with no matching `Python-urllib` entries in the log was written by `bootstrap_dtrack.py` against another instance, most likely AWS. That file is that instance's password: keep a copy before anything replaces it.
3. Hand the user the recovery procedure in `docs/start-fresh.md#recover-the-dependency-track-admin-password`. Writing a password hash is a credential change: the user runs it, and auto mode blocks the agent from doing so.
4. Meanwhile, offer `--keep-dtrack`, which clears LDE without the admin login.

`bootstrap_dtrack.py` serves a fresh Dependency-Track volume only. On a bootstrapped one it cannot recover a password. A local run writes the API key to `~/.lde/dtrack-api-key.txt` and into `.settings.json`.

**`port … is held by PID …`.** Report the process. The user decides whether it stops.

## Handling secrets

Read `~/.lde/dtrack-admin.txt` and `.settings.json` inside a Python process, and print counts, names and key prefixes only. This applies to any ad-hoc check you run against Dependency-Track, not just the script.

## Undo

- **LDE data:** deleted permanently, unless the run passed `--backup`, which moves it to `~/.lde/backups/lde-local-<UTC timestamp>/`. To restore a backup, stop the server and move the files back into `LDE_DATA_DIR` (the repo root locally).
- **Dependency-Track projects:** deleted permanently. To recover them, re-ingest from LDE.
