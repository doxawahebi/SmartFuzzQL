# FAQ

Quick answers to recurring questions. Each links to the doc with the full story.

### Do I need a Gemini API key just to try it?

No. Set `DEBUG_BYPASS_LLM=True` on the worker and the harness/patch stages use fixtures in
`backend/debug_assets/` while every other stage runs for real. A key is only needed for real LLM
output. See [getting-started.md](getting-started.md#no-gemini-key-yet).

### What's the fastest target to test with?

`sample://buffer-overflow` — a tiny bundled C project where input taint reaches `strcpy`. No
network, no build system. See [examples.md](examples.md).

### Why are there two pipelines (`tasks.py` and `pipeline.py`)?

`backend/tasks.py` is the Celery/FastAPI runtime that powers the dashboard; `pipeline.py` is a
standalone CLI that runs the same logical pipeline synchronously and writes a JSON report. They
share the SAST/patch helpers so they don't drift. See
[architecture.md](architecture.md#two-runtimes).

### CodeQL vs. Joern — which runs?

CodeQL runs first. If it can't build a database or finds nothing (and `JOERN_FALLBACK` is on,
the default), Joern takes over with a build-free analysis. `JOERN_FORCE=True` skips CodeQL
entirely. See [sast-analysis.md](sast-analysis.md) and [ADR-0001](adr/0001-joern-fallback.md).

### Why does the worker need the Docker socket?

To build and run an isolated fuzzing container per job. It's a real trust boundary — run the
worker only on infrastructure you control. See
[ADR-0002](adr/0002-docker-in-docker-per-job-env.md) and [SECURITY.md](../SECURITY.md).

### My CodeQL job died with exit code 137. Why?

That's an out-of-memory kill. Lower `CODEQL_RAM_MB` / `CODEQL_THREADS` or give Docker/WSL more
memory. See the [error catalog](operations.md#troubleshooting--error-catalog).

### Fuzzing runs but never finds a crash. Is that a bug?

Not necessarily — not every target crashes within the timeout, and the harness may be off. Check
the harness artifact and (in review mode) retry just the `AI_HARNESS` stage. A common cause is a
missing `__AFL_FUZZ_INIT()`, which is now injected defensively. See
[ADR-0003](adr/0003-llm-feedback-loops.md).

### `GET …/report` returns 409. What do I do?

The job isn't `SUCCESS` yet. Poll `GET /api/jobs/{id}` until `state == SUCCESS` (the 409 carries
an `X-Job-State` header), then fetch the report. See [api-spec.md](api-spec.md).

### The dashboard froze but the DB shows jobs completing — what happened?

The WebSocket relay likely wedged. It self-recovers with backoff; reloading the page re-hydrates
state over REST. This is the failure [ADR-0004](adr/0004-redis-pubsub-ws-relay.md) guards
against. See the [error catalog](operations.md#troubleshooting--error-catalog).

### Classic mode vs. review mode?

Classic runs all stages back to back and gives you a final report. Review mode pauses at each
stage for human approve/retry. Pick it with `review_mode: true` on `POST /api/jobs`. See
[ADR-0005](adr/0005-review-mode-editorial-pipeline.md).

### How do I change the LLM model?

At runtime via the Developer Lab (`POST /api/dev/llm-settings`), as a default via `GEMINI_MODEL`,
or add a new id to `ALLOWED_GEMINI_MODELS`. Don't add a second LLM SDK. See
[how-to.md](how-to.md#change-or-add-an-llm-model).

### Where do I report a security bug in the platform?

[SECURITY.md](../SECURITY.md) — privately, not via a public issue.

### Where do I get help / understand a term?

The docs index is [README.md](README.md); unfamiliar terms are in [glossary.md](glossary.md).
