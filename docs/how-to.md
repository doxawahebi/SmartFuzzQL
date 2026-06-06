# How-To Guides

Task-focused recipes that assume you already understand the basics (read
[architecture.md](architecture.md) first). Each one solves a real problem and points at the
authoritative reference for the details.

- [Add a new SAST query](#add-a-new-sast-query)
- [Add a REST endpoint](#add-a-rest-endpoint)
- [Add a frontend component / page](#add-a-frontend-component--page)
- [Add or modify a pipeline stage](#add-or-modify-a-pipeline-stage)
- [Run in debug / mock mode (no API key)](#run-in-debug--mock-mode-no-api-key)
- [Run the tcpdump end-to-end check](#run-the-tcpdump-end-to-end-check)
- [Change or add an LLM model](#change-or-add-an-llm-model)

---

## Add a new SAST query

CodeQL queries are picked up automatically by directory — no registration.

1. Drop the `.ql` into `backend/queries/vulnerabilities/` (findings) or
   `backend/queries/callgraph/` (reachability).
2. For a taint finding, use `@kind path-problem` so SARIF `codeFlows` (and therefore the
   `taint_path` graph) are produced.
3. If you add a **dangerous sink**, update all three so the taint query, call graph, and Python
   helpers stay consistent: `taint_buffer_overflow.ql`, `call_graph.ql`, and `DANGEROUS_FUNCS`
   in `tasks.py` — and, because of the Joern fallback, `INPUT_SOURCE_FUNCS`/`DANGEROUS_FUNCS` in
   `joern_analysis.py`.
4. `backend/test_joern.py` checks that the Joern adapter's SARIF still parses downstream.

Full mechanism: [sast-analysis.md](sast-analysis.md#adding-a-new-query).

---

## Add a REST endpoint

**Keep `main.py` thin** — endpoint definitions and the WS relay only; all heavy logic goes in
`tasks.py`.

1. Define Pydantic request/response schemas near the top of `backend/main.py` (follow the
   existing pattern).
2. Add the route function. Use `"job"` terminology in responses — never `"task"` or `"scan"`.
3. If it does pipeline/LLM work, put that in `tasks.py` and call it from the route.
4. **Update [api-spec.md](api-spec.md)** with the new contract (request, response, error codes).
   Don't change the shape of existing `/api/jobs` or `/ws` contracts without explicit sign-off —
   the frontend depends on them.
5. Add a `test_*.py` next to the module and run `pytest` + `black .`.

---

## Add a frontend component / page

1. Create the component in `frontend/src/` (flat layout) with a `PascalCase` filename.
2. Register the route in `frontend/src/main.jsx` if it's a page.
3. **Do not open a second WebSocket.** There is exactly one connection, created in
   `Dashboard.jsx` on mount. Pass event data down via props; new components consume that, they
   don't reconnect. REST is for hydration/history only — no polling for live state.
4. Follow the WS URL pattern (auto-detect `wss:`/`ws:`, host from `window.location`, port 8000)
   documented in [websocket.md](websocket.md) and `frontend/CLAUDE.md`.

---

## Add or modify a pipeline stage

A stage is a function in `backend/tasks.py` that takes the `PipelineContext` (and prior
`*StageResult`s) and returns its own dataclass result.

1. Write `_run_<stage>_stage(context, …) -> <Stage>StageResult` and slot it into `run_pipeline`
   in the correct order (see the stage table in [architecture.md](architecture.md#the-pipeline-stages)).
2. Emit progress **only** via `notify_status(task_id, step, status, details, extra)` — never
   touch the WebSocket from the worker. Use a new `step` name and document it in
   [websocket.md](websocket.md).
3. For recoverable failures, raise `PipelineUserError(message, hint)` so the `hint` surfaces as
   `error_hint`/`failure_detail` on the dashboard.
4. **Review-mode counterpart:** add the matching `run_review_<stage>_stage` task and update
   `REVIEW_STAGE_ORDER` and `REVIEW_DOWNSTREAM` (downstream-invalidation) in `tasks.py`. Keep the
   one-shot and review paths behaviorally consistent (see
   [ADR-0005](adr/0005-review-mode-editorial-pipeline.md)).
5. If the stage produces report data, persist it in `_run_db_storage_stage` and extend the
   `jobs` model + [database-schema.md](database-schema.md).

---

## Run in debug / mock mode (no API key)

Use the fixtures in `backend/debug_assets/` instead of calling Gemini — every non-LLM stage
still runs for real.

```bash
# in docker-compose.yml, set worker env: DEBUG_BYPASS_LLM=True
docker-compose up --build

# or for the CLI worker directly:
DEBUG_BYPASS_LLM=True celery -A tasks.celery_app worker --loglevel=info
```

This reads `mock_harness.c`, `mock_patch.c`, and `mock_deps.txt`. See
[configuration.md](configuration.md#debug--test-modes).

---

## Run the tcpdump end-to-end check

Verifies the full tcpdump-4.9.1 flow (the `bootp_print` structural finding) reaches a SUCCESS
report. Every real stage runs; a mock falls back only on failure, so the job always completes.

```bash
# in docker-compose.yml, set worker env: DEBUG_TEST_TCPDUMP=True
docker-compose up --build
```

Optionally point `TCPDUMP_CRASH_DIR` at a directory holding `harnss_crash.pcap` /
`origin_crash.pcap`. Independent of `DEBUG_BYPASS_LLM`. Tests: `backend/test_debug_tcpdump.py`.

---

## Change or add an LLM model

- **At runtime, no redeploy:** use the Developer Lab — `POST /api/dev/llm-settings` with a
  `model` from the allowed list (stored in the Redis `dev:llm_config` key). See
  [api-spec.md](api-spec.md).
- **As a new default:** set `GEMINI_MODEL`.
- **To allow a brand-new model id:** add it to `ALLOWED_GEMINI_MODELS` in `backend/tasks.py`
  (anything not in that list is silently ignored and falls back to the default). Do **not**
  introduce a second LLM SDK — route everything through `call_llm_api`.
