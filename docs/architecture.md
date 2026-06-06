# Architecture

This is the mental model: how SmartFuzzQL is wired, how data and control flow through it, the
core abstractions, and the two runtimes. For *why* the big decisions were made, follow the
links into the [ADRs](adr/README.md). For exhaustive contracts, see the reference docs
([api-spec](api-spec.md), [websocket](websocket.md), [database-schema](database-schema.md)).

## The one-sentence model

A **job** is one repository (or inline source) pushed through a fixed pipeline —
**SAST → AI_HARNESS → ENV_GEN → DAST → AI_PATCH → DB_STORAGE** — where static analysis finds a
taint bug, an LLM writes a fuzzing harness, AFL++ proves a crash, and an LLM proposes a patch;
progress streams to the browser the whole time.

## Service topology

Five services, defined in `docker-compose.yml`:

```
                 ┌────────────┐  REST + WebSocket   ┌──────────────┐
   browser  ───▶ │  frontend  │ ──────────────────▶ │     web      │  FastAPI
  (:5173)        │  (Vite)    │                     │   (:8000)    │  main.py
                 └────────────┘                     └──────┬───────┘
                                                           │ run_pipeline.delay()
                                          enqueue           ▼
                                       ┌──────────────────────────────┐
                                       │           redis (:6379)       │
                                       │  • Celery broker/result        │
                                       │  • PubSub "pipeline_logs"      │
                                       │  • key "dev:llm_config"        │
                                       └───────┬───────────────▲────────┘
                          consumes job          │ notify_status │ relay
                                                ▼               │
                                       ┌──────────────────────────────┐
                                       │           worker (Celery)      │  tasks.py
                                       │  mounts /var/run/docker.sock   │
                                       │  builds per-job fuzz containers│
                                       └───────┬────────────────────────┘
                                               │ persist
                                               ▼
                                       ┌──────────────────────────────┐
                                       │           db (Postgres 15)     │  jobs table
                                       └──────────────────────────────┘
```

- **`web`** (`backend/main.py`) — thin HTTP/WebSocket layer. Accepts jobs, serves status/report
  and admin/dev endpoints, and relays pipeline logs to `/ws`. **No pipeline logic lives here.**
- **`worker`** (`backend/tasks.py`) — all pipeline logic. Mounts the host Docker socket so it can
  build and run an isolated fuzzing container *per job* (see
  [ADR-0002](adr/0002-docker-in-docker-per-job-env.md)).
- **`redis`** — Celery broker/result backend, the `pipeline_logs` PubSub channel, and the
  Developer Lab's `dev:llm_config` override key.
- **`db`** — PostgreSQL; the single `jobs` table is the durable record (see
  [database-schema.md](database-schema.md)).
- **`frontend`** — React 18 + Vite dashboard; one WebSocket connection, REST for hydration/history.

## Request & control flow

```
User (dashboard) ──POST /api/jobs──▶ web (main.py)
                                       • create Job row (PENDING)
                                       • run_pipeline.apply_async((repo_url,), task_id=…)
                                       ◀── { task_id }

worker (tasks.py: run_pipeline) executes stage by stage:
   INIT → SAST → AI_HARNESS → ENV_GEN → DAST → AI_PATCH → DB_STORAGE → PIPELINE

Each stage calls notify_status(task_id, step, status, details, extra)
   → publishes JSON to Redis "pipeline_logs"

web (redis_listener) subscribes to "pipeline_logs"
   → updates in-memory job_store + Postgres (run_in_executor)
   → ConnectionManager.broadcast() to every /ws client

frontend receives the event, filters by task_id, and renders it live.
```

The decoupling of worker → Redis → web is deliberate: the Celery worker is a separate process
with no access to the FastAPI `ConnectionManager`, so it can only *publish*; the web process
*relays*. See [ADR-0004](adr/0004-redis-pubsub-ws-relay.md) for the failure-mode reasoning.

## The pipeline stages

| Stage (`step`) | Entry point in `tasks.py` | Does | Deep doc |
|----------------|---------------------------|------|----------|
| `INIT` | `_run_initialization_stage` | Clone the repo / materialise inline or `sample://` source into a temp workspace. | — |
| `SAST` | `_run_sast_stage` (→ `run_codeql_analysis`) | CodeQL two-pass; **falls back to Joern** if CodeQL can't build or finds nothing. Produces the vuln + taint/call graphs. | [sast-analysis.md](sast-analysis.md) |
| `AI_HARNESS` | `_run_ai_harness_stage` | LLM writes an AFL++ harness for the vulnerable function. | [dynamic-analysis.md](dynamic-analysis.md) |
| `ENV_GEN` | `build_dynamic_fuzzing_env` | LLM infers apt deps; builds a per-job fuzzing image from `Dockerfile.template`. | [dynamic-analysis.md](dynamic-analysis.md) |
| `DAST` | `_run_dast_stage` (→ `run_dast_fuzzing`) | Compile harness (with compiler-feedback retries), run AFL++, capture a crash. | [dynamic-analysis.md](dynamic-analysis.md) |
| `AI_PATCH` | `_run_ai_patch_stage` | Isolate the vulnerable function, LLM patches it, splice back. | [auto-remediation.md](auto-remediation.md) |
| `DB_STORAGE` | `_run_db_storage_stage` | Persist findings, graphs, crash, and patch to the `jobs` row. | [database-schema.md](database-schema.md) |
| `PIPELINE` | (terminal) | Emits the final `Success`/`Failed` event that sets `state`. | [websocket.md](websocket.md) |

Two of these stages lean on **LLM feedback loops** — if the harness won't compile or the Docker
image won't build, the stderr is fed back to the LLM for up to 3 retries
([ADR-0003](adr/0003-llm-feedback-loops.md)).

## Core abstractions

| Name | Where | Role |
|------|-------|------|
| `PipelineContext` | `tasks.py` | Per-job carrier: `task_id`, `repo_url`, `temp_dir`, `repo_path`. Threaded through every stage. |
| `SastStageResult` / `HarnessStageResult` / `DastStageResult` / `PatchStageResult` | `tasks.py` | Typed dataclass output of each stage; the input contract for the next. |
| `notify_status(task_id, step, status, details, extra)` | `tasks.py` | The **only** way to emit progress. Publishes to `pipeline_logs`. Never write to `/ws` from the worker. |
| `PipelineUserError(message, hint)` | `tasks.py` | A failure with an actionable `hint` (becomes `error_hint` on the WS event and `failure_detail` on the job). |
| SARIF → graph helpers (`_extract_taint_path`, `_extract_call_path`) | `tasks.py` | Convert CodeQL/Joern SARIF `codeFlows`/call edges into the `{nodes, edges}` graphs the report renders. |
| `call_llm_api(prompt, model, task_type)` | `tasks.py` | Single Gemini entry point (`google-genai`). Honours the dev override (`dev:llm_config`) and `DEBUG_BYPASS_LLM`. Do not add another LLM SDK. |

## Classic mode vs. review mode

A job runs in one of two modes, chosen by `review_mode` on `POST /api/jobs`:

- **Classic** (`review_mode: false`) — one shot. `run_pipeline` runs all stages back to back and
  the user sees the final report.
- **Review** (`review_mode: true`) — an *editorial* pipeline. Each stage runs as its own Celery
  task (`run_review_*_stage`), then **pauses** at a review gate (`review_state: "waiting"`). The
  user calls `POST …/review/approve` to advance or `…/review/retry` to redo a stage. Stage order
  and the downstream-invalidation rules live in `REVIEW_STAGE_ORDER` / `REVIEW_DOWNSTREAM` in
  `tasks.py`. Rationale: [ADR-0005](adr/0005-review-mode-editorial-pipeline.md).

The `jobs` table carries both: `current_stage`, `review_state`, `stage_results`, and
`stage_artifacts` are review-mode columns (see [database-schema.md](database-schema.md)).

## Two runtimes

The same logical pipeline exists in two places:

| | Compose pipeline (`backend/tasks.py`) | Standalone CLI (`pipeline.py`) |
|---|---|---|
| Orchestration | Celery tasks, async, queued | Synchronous, blocks per stage |
| Progress | `notify_status` → Redis → `/ws` | Rich console prints |
| Persistence | Postgres `jobs` table | `vulnerability_report.json` |
| Fuzzing image | Per-job, built from `Dockerfile.template` with LLM-injected deps | Fixed `hast-env` image |
| LLM | `call_llm_api` (Gemini flash by default) | `call_llm_api` (Gemini pro) |

They deliberately share the SAST/patch helpers (`joern_analysis.py`, `patching.py`) so the two
runtimes don't drift. Keep heavy logic in `tasks.py`/shared modules, never in `main.py`.

## Where to go next

- The *why* behind each tradeoff → [ADRs](adr/README.md)
- Exhaustive contracts → [api-spec.md](api-spec.md) · [websocket.md](websocket.md) · [database-schema.md](database-schema.md)
- Every config knob → [configuration.md](configuration.md)
