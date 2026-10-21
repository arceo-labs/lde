# Architecture

System topology for local development and the AWS ECS Fargate production deployment.
For the pipeline mechanics see `TRD.md` in the repository root. For the reasoning behind key design
choices see [Design decisions](decisions.md).

---

## Local development

```
  localhost (developer workstation)
  ─────────────────────────────────────────────────────────────────

  Browser
    │
    ▼
  python3 server.py                              :8002
    │                                              │
    └── github_sbom ──► api.github.com             │ BOM upload
                        (PAT auth)                 │ + search
                                                   ▼
                                           DT API server      :8081
                                           (docker compose)
                                                   │
                                                   │ H2 (embedded DB)

  DT Frontend   :8080   deep links only (docker compose)
  SQLite        ./depexplorer.db   runs · tasks
  Gemini API    optional — package extraction from URLs / files
```

---

## AWS ECS Fargate (production)

```
  AWS account
  ─────────────────────────────────────────────────────────────────

  Internet
    │
    ▼
  Application Load Balancer  (HTTPS · ACM cert)
    │                    │
    │ lde.domain.com     │ dtrack.domain.com
    ▼                    ▼
  LDE                DT Frontend
  Fargate            Fargate
  0.25 vCPU / 0.5 GB 0.25 vCPU / 0.5 GB
    │                    │
    │                    │ Cloud Map (internal DNS)
    │                    ▼
    └──────────────► DT API Server
                     Fargate · 0.5 vCPU / 2 GB
                          │
                          ▼
                     Aurora PostgreSQL
                     RDS Serverless v2

  LDE side-connections:
  ├── EFS  /app/data  ── depexplorer.db · run logs (persistent across restarts)
  ├── Secrets Manager ── lde/github-pat · lde/dtrack-api-key
  │                      lde/gemini-api-key · lde/basic-auth
  ├── api.github.com        (github_pats · github_sbom ingest)
  └── generativelanguage.googleapis.com   (gemini_api_key · optional)
```
