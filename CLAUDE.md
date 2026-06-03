# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SmartFuzzQL (HAST)** is an automated C/C++ security vulnerability analysis platform that chains:
1. **CodeQL SAST** — finds taint-flow bugs (e.g., `strcpy` buffer overflows) in a target GitHub repo
2. **LLM (Gemini)** — auto-generates an AFL++ fuzzing harness; feedback-loops on compile errors
3. **AFL++ DAST** — fuzzes the compiled harness in an isolated Docker container to prove a crash
4. **LLM (Gemini)** — generates a patch for the vulnerable code
5. **Reporting** — surfaces results in a React dashboard (React Flow + Monaco diff viewer)

## Running the Full Stack

```bash
# Start all services (FastAPI, Celery worker, Redis, PostgreSQL, React frontend)
GEMINI_API_KEY=<your_key> docker-compose up --build

# Frontend: http://localhost:5173
# Backend API: http://localhost:8000
```

## Running the Standalone Pipeline (CLI mode)

```bash
# Activate venv
source .venv/bin/activate

# Requires GEMINI_API_KEY and Docker daemon running
GEMINI_API_KEY=<key> python pipeline.py <github_repo_url> [--branch <branch>]
```

## Backend Development

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run FastAPI server (dev)
uvicorn main:app --reload --port 8000

# Run Celery worker (separate terminal)
celery -A tasks.celery_app worker --loglevel=info

# Debug mode: bypass real LLM calls with fixture files
DEBUG_BYPASS_LLM=True celery -A tasks.celery_app worker --loglevel=info
```

Debug mode reads from `backend/debug_assets/mock_harness.c`, `mock_patch.c`, `mock_deps.txt` instead of calling Gemini.

## Frontend Development

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173
npm run build    # production build
```

## Architecture

### Request Flow

```
User (dashboard) → POST /api/jobs → FastAPI (main.py)
                                    → run_pipeline.delay() [Celery task]
                                    ← task_id

Celery worker (tasks.py) executes the pipeline:
  SAST → AI_HARNESS → DAST → AI_PATCH → DB_STORAGE

Progress is published to Redis PubSub "pipeline_logs" channel.
FastAPI subscribes and relays messages over WebSocket (/ws).
Frontend receives real-time status via WebSocket.
```

### Key Files

| File | Purpose |
|------|---------|
| `backend/main.py` | FastAPI app: `/api/jobs` (POST), `/ws` (WebSocket), Redis PubSub relay |
| `backend/tasks.py` | Celery tasks: `run_pipeline` (main pipeline), `build_dynamic_fuzzing_env` (Docker image builder) |
| `backend/custom.ql` | CodeQL query: taint tracking from function parameters to `strcpy` sink |
| `backend/Dockerfile.template` | AFL++ Ubuntu 22.04 image template; `{{ TARGET_DEPS }}` is replaced by LLM-suggested apt packages |
| `pipeline.py` | Standalone CLI version of the same pipeline (no Celery/FastAPI) |
| `custom.ql` | Root-level CodeQL query (used by the CLI pipeline) |

### Docker-in-Docker Pattern

The Celery worker mounts `/var/run/docker.sock` so it can spin up per-job fuzzing containers. The `Dockerfile.template` is used to build a fresh image per task — Layer 4 injects LLM-determined apt dependencies, keeping earlier layers cached.

### LLM Integration

Both `pipeline.py` and `backend/tasks.py` call Gemini via `google-genai`. The model used is `gemini-2.5-pro` (CLI) or `gemini-2.5-flash` (web backend). Set `GEMINI_API_KEY` as an env var. The `call_llm_api` function in `tasks.py` supports `task_type` for debug-mode dispatch.

### Feedback Loops

- **Harness compile failure:** compiler stderr is fed back to the LLM for up to 3 retries
- **Dockerfile build failure:** docker build stderr is fed back to the LLM for up to 3 retries
- **Fuzzing timeout:** AFL++ stats are fed back to the LLM to adjust the harness

## Environment Variables

| Variable | Service | Purpose |
|----------|---------|---------|
| `GEMINI_API_KEY` | worker | Required for LLM calls |
| `CELERY_BROKER_URL` | web, worker | Redis URL (default: `redis://redis:6379/0`) |
| `CELERY_RESULT_BACKEND` | web, worker | Redis URL |
| `DATABASE_URL` | web, worker | PostgreSQL connection string |
| `DEBUG_BYPASS_LLM` | worker | Set `True` to skip Gemini and use fixture files |
| `JOERN_FALLBACK` | worker | Default `True`. Build-free Joern SAST fallback when CodeQL fails to build or finds nothing; `False` = CodeQL-only |
| `JOERN_FORCE` | worker | Default `False`. Skip CodeQL and run Joern directly (testing the Joern path) |
| `DEBUG_TEST_TCPDUMP` | worker | Set `True` to verify the full tcpdump-4.9.1 flow end-to-end: every real stage still runs, but a mock falls back on failure so the job always reaches a SUCCESS `bootp_print` report. Independent of `DEBUG_BYPASS_LLM`. |
| `TCPDUMP_CRASH_DIR` | worker | Optional override for the directory holding the real crash pcaps (`harnss_crash.pcap`, `origin_crash.pcap`); defaults to `backend/debug_assets`. |

## Commands (Quick Reference)

- Build (full stack): `docker-compose up --build`
- Build (frontend only): `cd frontend && npm run build`
- Build (C test target): `make` (compiles `test/vuln.c`)
- Test (backend): `pytest`
- Lint/Format (backend): `black .`
- Run Dev (backend): `cd backend && uvicorn main:app --reload --port 8000`
- Run Dev (frontend): `cd frontend && npm run dev`

## Project Architecture & Structure

- `backend/main.py`: Thin API layer — HTTP endpoints and WebSocket relay only.
- `backend/tasks.py`: All pipeline logic lives here as Celery tasks.
- `frontend/src/`: React dashboard (`Dashboard.jsx` is the single-page app).
- `pipeline.py`: Standalone CLI that mirrors the Celery pipeline without FastAPI/Redis.
- *Rule*: Keep `main.py` thin — never put pipeline or LLM logic there. Heavy work belongs in `tasks.py`.

## Code Style & Conventions

- Backend: Python, FastAPI; `snake_case` for functions/variables, `PascalCase` for classes.
- Frontend: JavaScript/JSX (React 18, Vite); `PascalCase` for components, `camelCase` for functions/variables.
- Formatting: Run `black .` before committing backend changes.
- Avoid: Do not introduce a new LLM SDK — use `google-genai` (`call_llm_api` in `tasks.py`) for all LLM calls.

## Testing & API Conventions

- Backend test location: Place `test_*.py` files next to the module they test (e.g., `backend/test_tasks.py`).
- Before Commit: `black .` must show no changes; run `pytest` if tests exist.
- Domain Rule: Always use "job" for a pipeline run in API responses and UI — never "task" (Celery's internal term) or "scan".

## Guardrails & Priorities

- Critical: Never hardcode `GEMINI_API_KEY` or any credentials — pass via environment variables or a `.env` file excluded from git.
- Docker template: Do not alter the structure of `backend/Dockerfile.template`; the `{{ TARGET_DEPS }}` placeholder is required for per-job LLM dependency injection.
- Refactoring: Do not break existing `/api/jobs` or `/ws` contracts without explicit permission.
- Conflict Resolution: If performance and readability conflict, prioritize readability.

## Documentation

Detailed reference documents live in `docs/`. Always consult these before adding or changing API or WebSocket behaviour:

| Document | Covers |
|----------|--------|
| `docs/api-spec.md` | All REST, Developer Lab, and admin endpoint contracts, schemas, error codes, env vars |
| `docs/websocket.md` | WebSocket event schema, step lifecycle, backend and frontend integration |
| `docs/sast-analysis.md` | SAST stage: CodeQL two-pass analysis, query packs, taint/call-path graphs |
| `docs/dynamic-analysis.md` | AI_HARNESS + DAST + ENV_GEN: harness generation, Docker env build, AFL++ fuzzing, `sample://` protocol |
| `docs/auto-remediation.md` | AI_PATCH stage: patch generation, persistence, report rendering |
| `docs/auto-remediation-gaps.md` | Known limitations of the patching stage |

Sub-CLAUDE.md files with per-directory guidance:

- `backend/CLAUDE.md` — backend rules, API contract rules, WebSocket publish path
- `frontend/CLAUDE.md` — frontend rules, WebSocket client pattern, component conventions

## Deep Dive References

- Standalone pipeline flow: `pipeline.py`
- AFL++ Docker image template: `backend/Dockerfile.template`
- Debug/mock assets: `backend/debug_assets/`
