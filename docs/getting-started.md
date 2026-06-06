# Getting Started

This page takes you from a clean checkout to a **finished vulnerability report** in a few
minutes. It holds your hand — if you have never run SmartFuzzQL before, do exactly what is
written here, in order.

> **What you are about to do:** start the full stack with Docker Compose, submit the built-in
> `sample://buffer-overflow` target, and watch one *job* run through the pipeline
> (SAST → harness → fuzz → patch) until it reaches `SUCCESS` and renders a report.

---

## 1. Prerequisites

| Requirement | Why | Check |
|-------------|-----|-------|
| **Docker + Docker Compose** | The whole stack (API, worker, Redis, Postgres, frontend) runs in containers, and the worker builds *per-job* fuzzing containers. | `docker --version && docker compose version` |
| **~8 GB RAM free** | CodeQL database builds are memory-hungry; the default cap is `CODEQL_RAM_MB=2048` per pass. On WSL2, raise the VM memory if builds get OOM-killed (exit 137). | — |
| **Free ports 8000, 5173, 6379, 5432** | web API, frontend, Redis, Postgres. | `ss -ltn` |
| **A Gemini API key** | The harness- and patch-generation stages call Google Gemini through `call_llm_api()`. You can skip this for a first run — see [the no-key path](#no-gemini-key-yet). | env var `GEMINI_API_KEY` |
| **Git** | The pipeline clones GitHub targets. (Not needed for the `sample://` target.) | `git --version` |

The standalone CLI (`pipeline.py`) additionally needs the Docker daemon reachable and a Python
3.11+ virtualenv. The CLI is optional — the Compose stack is the recommended path.

---

## 2. Start the full stack

From the repo root:

```bash
GEMINI_API_KEY=<your_key> docker-compose up --build
```

This starts five services (see [architecture.md](architecture.md) for the topology):

| Service | URL / port | Role |
|---------|-----------|------|
| `frontend` | http://localhost:5173 | React dashboard |
| `web` | http://localhost:8000 | FastAPI: REST + `/ws` |
| `worker` | — | Celery worker that runs the pipeline |
| `redis` | localhost:6379 | Celery broker + pipeline-log PubSub |
| `db` | localhost:5432 | PostgreSQL (`hast_db`, user `user` / password `password`) |

Wait until the logs settle and the frontend compiles. Then open **http://localhost:5173**.

### No Gemini key yet?

You can do a full end-to-end run **without** a real key by telling the worker to use the
fixture responses in `backend/debug_assets/` instead of calling Gemini. Stop the stack, then:

```bash
# edit docker-compose.yml: under `worker.environment`, set DEBUG_BYPASS_LLM=True
docker-compose up --build
```

In `DEBUG_BYPASS_LLM` mode the SAST, fuzzing and Docker stages still run for real; only the
LLM calls are replaced by `mock_harness.c` / `mock_patch.c`. See
[configuration.md](configuration.md) for every debug toggle.

---

## 3. Run the minimal example

### From the dashboard

1. Open http://localhost:5173 (the **Project Dashboard**).
2. In the target input, choose the **`sample://buffer-overflow`** sample (a tiny C project
   where `argv`/input taint reaches `strcpy`). This needs no network and is the fastest target.
3. Press **Start**. Watch the left sidebar walk through the stages and the log cards stream in
   real time over the WebSocket.
4. When the job reaches **SUCCESS**, open the **Report** (`/report/:id`): the left panel shows
   the source→sink taint graph, the right panel a Monaco diff of the vulnerable vs. patched code.

### From the API (equivalent)

```bash
# submit the sample target
curl -s -X POST http://localhost:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{"repo_url": "sample://buffer-overflow", "submitted_by": "you@example.com"}'
# -> {"message":"Job submitted successfully","task_id":"<uuid>"}

# poll status until state == SUCCESS
curl -s http://localhost:8000/api/jobs/<uuid> | python -m json.tool

# fetch the full report (200 only once state == SUCCESS; 409 with X-Job-State otherwise)
curl -s http://localhost:8000/api/jobs/<uuid>/report | python -m json.tool
```

More snippets (inline source, WebSocket client, review mode) are in [examples.md](examples.md).

---

## 4. What success looks like

- The job's `state` transitions `PENDING → STARTED → SUCCESS`.
- `GET /api/jobs/{id}` returns a `vuln` block (message + file) and a `result` block with
  `patch_generated: true` and a `crash_hex`.
- `GET /api/jobs/{id}/report` returns a `taint_path`, a `diff` (original vs. patched), and the
  crash input as hex.

If the job ends in **FAILURE**, read the `failure_detail` field and head to the
[troubleshooting & error catalog](operations.md#troubleshooting--error-catalog).

---

## 5. Standalone CLI (optional)

The same pipeline runs without Celery/FastAPI via `pipeline.py`:

```bash
source .venv/bin/activate          # Python 3.11+ with backend/requirements.txt installed
GEMINI_API_KEY=<key> python pipeline.py https://github.com/<owner>/<repo> --branch main
```

It writes `vulnerability_report.json` and uses a fixed `hast-env` Docker image. Differences
from the Compose pipeline are covered in [architecture.md](architecture.md#two-runtimes).

---

## What next

- Understand how it all fits together → [architecture.md](architecture.md)
- Look up an endpoint or env var → [api-spec.md](api-spec.md), [configuration.md](configuration.md)
- Extend the system (new query, endpoint, stage) → [how-to.md](how-to.md)
- Something broke → [operations.md](operations.md#troubleshooting--error-catalog)
