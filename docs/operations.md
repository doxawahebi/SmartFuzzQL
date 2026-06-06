# Operations

Running, observing, and debugging SmartFuzzQL. For the config knobs referenced throughout, see
[configuration.md](configuration.md).

## Deployment

The supported deployment is Docker Compose (`docker-compose.yml`):

```bash
GEMINI_API_KEY=<key> docker-compose up --build
```

Five services come up — `web` (:8000), `worker`, `redis` (:6379), `db` (:5432), `frontend`
(:5173). Topology and roles: [architecture.md](architecture.md#service-topology).

### Things that matter in any environment

- **Docker socket mount.** The `worker` mounts `/var/run/docker.sock` so it can build and run a
  fuzzing container per job. This is effectively host-root access — only deploy the worker on
  infrastructure you control, and never expose it to untrusted submitters. See
  [ADR-0002](adr/0002-docker-in-docker-per-job-env.md) and [SECURITY.md](../SECURITY.md).
- **Memory.** CodeQL database builds are the main memory consumer (`CODEQL_RAM_MB`, default
  2048 per pass). On WSL2/low-RAM hosts, raise the Docker VM memory or lower
  `CODEQL_RAM_MB`/`CODEQL_THREADS` to avoid OOM kills.
- **Concurrency.** `CELERY_WORKER_CONCURRENCY` (default 1). Each concurrent job builds and runs
  its own container, multiplying CPU/RAM/disk — scale deliberately.
- **Secrets.** `GEMINI_API_KEY` via env/`.env` only; never commit it. CORS is `*` in dev — lock
  it down before any non-local deployment.
- **Persistence.** Postgres data lives in the `postgres_data` volume; the `jobs` table is the
  durable record. `init_db()` creates/evolves the schema on web startup (see
  [database-schema.md](database-schema.md)).

### Per-environment config

Override via env vars in your Compose file or orchestrator: point `DATABASE_URL`,
`CELERY_BROKER_URL`, and `CELERY_RESULT_BACKEND` at managed Postgres/Redis; set `GEMINI_MODEL`
and resource caps to match the box. Everything tunable is in
[configuration.md](configuration.md).

## Monitoring & observability

| Signal | Where | What it tells you |
|--------|-------|-------------------|
| Worker logs | `docker compose logs -f worker` | Per-stage progress, Rich console output, tracebacks. The primary debugging surface. |
| Web logs | `docker compose logs -f web` | API errors and the `[relay]` lines from `redis_listener` (subscribe/reconnect). |
| Pipeline events | Redis channel `pipeline_logs` / the `/ws` stream | Every `notify_status` event (step/status/details, `error_hint`). Same data the dashboard shows. |
| Job state | Postgres `jobs` table | Durable truth: `state`, `current_stage`, `review_state`, `failure_detail`. See [database-schema.md](database-schema.md). |
| Admin dashboard | `GET /admin/dashboard*` | Aggregate counts, recent jobs, per-user stats. |

Inspect events straight from Redis:

```bash
docker compose exec redis redis-cli SUBSCRIBE pipeline_logs
```

Inspect a stuck job in the DB:

```bash
docker compose exec db psql -U user -d hast_db \
  -c "select task_id,state,current_stage,review_state,failure_detail from jobs order by submitted_at desc limit 5;"
```

## Troubleshooting & error catalog

Symptom → likely cause → fix. Recoverable pipeline failures raise `PipelineUserError` whose
`hint` surfaces as `error_hint` on `/ws` and `failure_detail` on the job — **always read
`failure_detail` first.**

### Pipeline failures

| Symptom / signal | Cause | Fix |
|------------------|-------|-----|
| Job FAILURE at `SAST`; logs mention exit code `137` | CodeQL OOM-killed | Lower `CODEQL_RAM_MB` and/or `CODEQL_THREADS`; increase Docker/WSL memory. |
| Job FAILURE at `SAST`, "no vulnerability found" | CodeQL built nothing **and** Joern disabled or also empty | Ensure `JOERN_FALLBACK=True`; try `JOERN_FORCE=True` to test the Joern path; confirm the target actually contains a taint-to-sink pattern. |
| `SAST` Joern errors about JVM/Java | Joern needs JDK ≥ 17 | Use the provided images (Joern at `/opt/joern/joern-cli`); don't run Joern on a host without JDK 17+. |
| Job FAILURE at `DAST`, "harness failed to compile" after retries | LLM harness wrong 3× | Inspect the harness artifact + compiler stderr in the logs. Often a missing include or signature mismatch; retry, or in review mode fix and retry just that stage. |
| Fuzzing runs but never crashes; AFL++ persistent-mode errors | Harness missing `__AFL_FUZZ_INIT()` | `_ensure_afl_fuzz_init()` injects it defensively; if it still fails, the harness loop shape is wrong — retry the `AI_HARNESS` stage. See [ADR-0003](adr/0003-llm-feedback-loops.md). |
| Job FAILURE at `ENV_GEN`, `docker build` fails after retries | LLM apt-dependency guess wrong 3× | Read the `docker build` stderr in the worker logs; the target may need a dep the model can't infer — add it and retry. |
| `ENV_GEN`/`DAST` errors: "Cannot connect to the Docker daemon" | Worker can't reach Docker | Confirm `/var/run/docker.sock` is mounted into the worker and the host daemon is running. |

### LLM

| Symptom | Cause | Fix |
|---------|-------|-----|
| Immediate failure in `AI_HARNESS`/`AI_PATCH`, auth/4xx in logs | Missing/invalid `GEMINI_API_KEY` | Set a valid key (env or Developer Lab). To run without a key, use `DEBUG_BYPASS_LLM=True`. |
| LLM 429 / quota / rate-limit | Gemini quota exhausted | Wait/raise quota, or switch model via `GEMINI_MODEL` / Developer Lab. |
| Model change ignored | Value not in `ALLOWED_GEMINI_MODELS` | Use an allowed id, or add it to `ALLOWED_GEMINI_MODELS` in `tasks.py`. |

### API / dashboard

| Symptom | Cause | Fix |
|---------|-------|-----|
| `POST /api/jobs` → 400 | Bad target shape | `repo` needs `repo_url`; `source` needs `source_code`; `target_type` ∈ {repo, source}. See [api-spec.md](api-spec.md). |
| `POST /api/jobs` → 503 "Celery broker unavailable" | Redis/worker down | Check `redis` and `worker` containers and `CELERY_BROKER_URL`. |
| `GET …/report` → 409 with `X-Job-State` | Job not yet SUCCESS | Poll `GET /api/jobs/{id}` until `state == SUCCESS`, then fetch the report. |
| Review approve/retry → 409 | Job not in `review_state: "waiting"` (or stage mismatch) | Only act on a stage that is actually waiting; pass the matching `stage`. |
| Dashboard frozen but jobs still complete in DB | The WS relay wedged | This is the failure [ADR-0004](adr/0004-redis-pubsub-ws-relay.md) guards against. Check `web` logs for `[relay]` errors; the relay self-recovers with backoff, otherwise restart `web`. A page reload re-hydrates state over REST. |
| Dashboard shows nothing live | WS not connected | Confirm `/ws` reachable on port 8000; the client auto-reconnects every 3s. |

For the HTTP error codes per endpoint, see [api-spec.md](api-spec.md). For the WS event/step
lifecycle, see [websocket.md](websocket.md).
