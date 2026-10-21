# AGENTS.md

## Set the LDE password before opening the site

On an AWS deploy, run `python3 scripts/set_lde_password.py` before `terraform plan`. The script asks for a username and password and writes `~/.lde/basic-auth.json`. Plan fails when that file is missing. `https://<lde_domain>` returns 401 until this has been done.

The browser username is the JSON key. The browser password is the plaintext, also stored in `~/.lde/lde-admin.txt`.

Dependency-Track is a second login. Set it with `scripts/bootstrap_dtrack.py` on a fresh instance, which saves the admin login to a 0600 file. A blank local volume should use `--password-out ~/.lde/dtrack-admin.local.txt` so `~/.lde/dtrack-admin.txt` is not overwritten if it holds another instance. For AWS pass `--password-out ~/.lde/dtrack-admin.aws.txt`. Local bootstrap also copies the API key into `.settings.json`. A password set by hand in the browser is saved nowhere. To recover a lost local password, the user runs `scripts/reset_dtrack_admin.py`. `start_fresh.py` reports factory vs mismatched vs matching admin state; it does not rotate the password.

Run `python3 scripts/check_aws.py preflight` before any AWS `terraform plan` and `python3 scripts/check_aws.py verify` after any apply or secret change. Claude's `start-fresh-aws` skill covers the judgement calls.

Local `python3 server.py` serves with no password. Set `basic_auth_credentials` only when you want that gate.

## Start the local stack

Run `python3 scripts/start_fresh.py` to start, restart or reset the local stack. Without `--yes` and without a terminal, it prints its plan and exits unchanged: show that plan to the user before clearing anything. Clearing deletes LDE data permanently; `--backup` keeps a copy. Claude's `start-fresh-local` skill covers the judgement calls.
