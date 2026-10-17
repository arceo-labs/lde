# Library Dependency Explorer

A locally hosted web app that indexes every direct and transitive dependency across your GitHub organizations — without cloning a single repository.

## Ingest method

The UI starts **github_sbom** runs only: GitHub's Dependency Graph API, no Docker. A full org scan completes in 2–5 minutes. Repos with the Dependency Graph disabled are marked `skipped`.

ORT, the former local Docker pipeline, is deprecated. See [Design decisions](decisions.md#2-ort-pipeline-deprecated).

## Quick start

AWS deploys: run `python3 scripts/set_lde_password.py` before `terraform plan`. Plan fails without `~/.lde/basic-auth.json`. The browser username is the one you typed. The browser password is the plaintext in `~/.lde/lde-admin.txt`. For Dependency-Track, run `scripts/bootstrap_dtrack.py` as in [the AWS guide](aws-deployment.md) Step 5, with `--password-out ~/.lde/dtrack-admin.aws.txt`. Use that file for the Dependency-Track UI. `~/.lde/dtrack-admin.txt` is the local instance's login.

```bash
python3 server.py          # serves on http://localhost:8002
```

Open `http://localhost:8002` → **Settings** → paste a GitHub PAT → **Save**.

Then go to **Ingest Dependencies**, enter an org name, and click **Start run**.

## Key settings

| Setting key | Description |
|---|---|
| `github_pat` | GitHub fine-grained PAT (Contents: Read-only, Metadata: Read-only) |
| `dtrack_url` | Dependency-Track API server URL (default: `http://localhost:8081`) |
| `dtrack_ui_url` | Dependency-Track frontend URL for deep links (default: `http://localhost:8080`) |
| `basic_auth_credentials` | JSON string `{"admin": "<sha256_hex>"}` — omit to disable auth in local dev |

Settings are stored in `.settings.json` (gitignored). See `.settings.json.example` for all keys.
In production, settings are injected via AWS Secrets Manager (`LDE_SECRETS_SOURCE=aws`).

## Documentation

- [**Usage guide**](usage.md) — end-to-end walkthrough with a real supply chain advisory example
- [Settings reference](settings.md) — every configuration key, default, and override method
- [Package Search](pkg-search.md) — search for vulnerable packages across all repos
- [AWS ECS Setup](aws-deployment.md) — deploy to Fargate with Terraform
- [AWS cost control](aws-cost-control.md) — measured costs, what was cut and what is left
