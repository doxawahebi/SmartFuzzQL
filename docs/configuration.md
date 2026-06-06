# Configuration Reference

The authoritative, consolidated list of every environment variable and configuration knob.
Per-endpoint configuration lives in [api-spec.md](api-spec.md); the schema of stored data is in
[database-schema.md](database-schema.md). Defaults below are the values baked into the code /
`docker-compose.yml`.

## How configuration is supplied

| Mechanism | Used for | Notes |
|-----------|----------|-------|
| Environment variables | Almost everything (see tables below) | Set in `docker-compose.yml` or your shell. The worker reads these via `os.environ`. |
| `.env` file | Secrets like `GEMINI_API_KEY` | Excluded from git. **Never hardcode credentials.** |
| Redis key `dev:llm_config` | Runtime LLM override (model / API key / bypass) | Set through `POST /api/dev/llm-settings` (the Developer Lab). Takes precedence over `GEMINI_MODEL` / `GEMINI_API_KEY`. |

**Precedence for the LLM model:** `dev:llm_config.model` → `GEMINI_MODEL` → the function default
(`gemini-2.5-flash`). **For the API key:** `dev:llm_config.api_key` → `GEMINI_API_KEY`. (See
`call_llm_api` and `_dev_llm_response` in `backend/tasks.py` / `backend/main.py`.)

## Core services

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `CELERY_BROKER_URL` | web, worker | `redis://redis:6379/0` (compose) / `redis://localhost:6379/0` (code) | Celery broker **and** the Redis used for the `pipeline_logs` PubSub relay. |
| `CELERY_RESULT_BACKEND` | web, worker | same as broker | Celery result backend. |
| `DATABASE_URL` | web, worker | `postgresql://user:password@db:5432/hast_db` | PostgreSQL connection string (read in `backend/database.py`). |
| `CELERY_WORKER_CONCURRENCY` | worker | `1` | Celery `--concurrency`. Each concurrent job builds its own fuzzing container, so raise with care. |

## LLM (Gemini)

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `GEMINI_API_KEY` | worker | _(unset)_ | **Required** for real LLM calls (harness + patch). Pass via env/`.env`, never hardcode. Overridden by a key set in the Developer Lab. |
| `GEMINI_MODEL` | worker | `gemini-2.5-flash` | Override the default model. Must be one of the allowed models below, else it's ignored. |

**Allowed models** (`ALLOWED_GEMINI_MODELS` in `tasks.py`): `gemini-2.5-flash` (default),
`gemini-3-flash-preview`, `gemini-3.5-flash`. The standalone CLI defaults to a Gemini *pro* model.

## SAST engine (CodeQL / Joern)

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `CODEQL_THREADS` | worker | `1` | `--threads` for both CodeQL analyze passes. |
| `CODEQL_RAM_MB` | worker | `2048` | `--ram` for CodeQL. If CodeQL is OOM-killed (exit `137`), **lower** this and/or `CODEQL_THREADS`, or give Docker/WSL more memory. |
| `JOERN_FALLBACK` | worker | `True` | Build-free Joern fallback when CodeQL fails to build or finds nothing. Set `False` for CodeQL-only. |
| `JOERN_FORCE` | worker | `False` | Skip CodeQL entirely and run Joern directly (for testing the Joern path). |

See [sast-analysis.md](sast-analysis.md) and [ADR-0001](adr/0001-joern-fallback.md).

## Debug & test modes

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `DEBUG_BYPASS_LLM` | worker | `False` | Skip Gemini and use fixtures in `backend/debug_assets/` (`mock_harness.c`, `mock_patch.c`, `mock_deps.txt`). Every non-LLM stage still runs for real. Lets you run end-to-end with no API key. |
| `DEBUG_TEST_TCPDUMP` | worker | `False` | Resilience mode for the tcpdump-4.9.1 end-to-end check: every real stage runs, but a mock falls back on failure so the job always reaches a SUCCESS `bootp_print` report. Independent of `DEBUG_BYPASS_LLM`. |
| `TCPDUMP_CRASH_DIR` | worker | `backend/debug_assets` | Override the directory holding the real crash pcaps (`harnss_crash.pcap`, `origin_crash.pcap`) used by `DEBUG_TEST_TCPDUMP`. |

## Review mode

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `PIPELINE_WORKSPACE_ROOT` | worker | `backend/.runtime/workspaces` | Root directory for per-job review-mode workspaces (cloned repo / inline source / SARIF / fuzz I/O). |

## Frontend

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `VITE_API_URL` | frontend | `http://localhost:8000` | Backend base URL for the dev server. Note: at runtime the dashboard also derives the API/WS host from `window.location` (always port 8000). |

## CLI-only (`pipeline.py`)

The standalone CLI reads `GEMINI_API_KEY`, `JOERN_FALLBACK`, and `JOERN_FORCE` with the same
semantics as above. It uses a fixed Docker image name `hast-env` and a hard-coded fuzz timeout
(`FUZZ_TIMEOUT_SEC = 20 min`); these are constants in `pipeline.py`, not env vars.

## Persistent volumes & ports (compose)

| Item | Value |
|------|-------|
| Exposed ports | web `8000`, frontend `5173`, redis `6379`, db `5432` |
| Postgres volume | `postgres_data` → `/var/lib/postgresql/data` |
| Worker mount | `/var/run/docker.sock` (required for per-job fuzzing containers — see [ADR-0002](adr/0002-docker-in-docker-per-job-env.md)) |
