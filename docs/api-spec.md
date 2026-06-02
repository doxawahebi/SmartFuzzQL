# HAST Pipeline API Specification

**Version:** 1.0  
**Base URL:** `http://<host>:8000`  
**Authentication:** None (development)

---

## REST Endpoints

### POST /api/jobs

Submit a new pipeline job for a target GitHub repository.

**Request**
```json
{
  "repo_url": "https://github.com/example/vulnerable-repo",
  "submitted_by": "user@example.com"
}
```

`submitted_by` is optional (defaults to `null`). It is stored for admin reporting only —
it is **not** used for authentication. `repo_url` also accepts the `sample://` protocol for
the bundled sample repositories (see Developer Lab Endpoints below).

**Response 200**
```json
{
  "message": "Job submitted successfully",
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Review-mode request (optional)**
```json
{
  "target_type": "repo",
  "repo_url": "https://github.com/example/vulnerable-repo",
  "review_mode": true
}
```

For inline C/C++ source review:
```json
{
  "target_type": "source",
  "source_code": "void f(char *s) { char b[8]; strcpy(b, s); }",
  "review_mode": true
}
```

When `review_mode=true`, the backend enqueues stage-specific Celery tasks and pauses for review after `SAST`, `AI_HARNESS`, `DAST`, and `AI_PATCH`.

**Response 503** — the Celery broker is unavailable and the job could not be queued.

---

### GET /api/jobs

List all submitted jobs (in-memory, current process lifetime).

**Response 200** — array of `JobSummary`
```json
[
  {
    "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "state": "SUCCESS",
    "repo_url": "https://github.com/example/vulnerable-repo",
    "submitted_at": "2026-05-31T12:00:00+00:00"
  }
]
```

**State values:** `PENDING` | `STARTED` | `SUCCESS` | `FAILURE`

---

### GET /api/jobs/{task_id}

Get the current status and enriched results for a specific job.

**Path parameter:** `task_id` — UUID returned from `POST /api/jobs`

**Response 200** — `JobStatusResponse`
```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "state": "SUCCESS",
  "repo_url": "https://github.com/example/vulnerable-repo",
  "target_type": "repo",
  "review_mode": true,
  "current_stage": "AI_PATCH",
  "review_state": "waiting",
  "stage_artifacts": {},
  "failure_detail": null,
  "vuln": {
    "message": "Potential buffer overflow",
    "file": "src/main.c",
    "code_snippet": "void vulnerable_func(char* input) { char buf[10]; strcpy(buf, input); }"
  },
  "result": {
    "repo": "https://github.com/example/vulnerable-repo",
    "vuln_msg": "Potential buffer overflow",
    "vuln_file": "src/main.c",
    "patch_generated": true,
    "crash_hex": "4141414141414141414141",
    "patch_code": "#include <string.h>\nvoid vulnerable_func(char* input) { char buf[10]; strncpy(buf, input, 9); buf[9] = '\\0'; }"
  }
}
```

**Response 404**
```json
{ "detail": "Job not found" }
```

`vuln` and `result` are `null` until the corresponding pipeline steps complete.

---

### POST /api/jobs/{task_id}/review/approve

Approve the current waiting review stage and enqueue the next stage.

**Request body**
```json
{
  "stage": "SAST"
}
```

`stage` is optional for older callers. When present, it must match the server-side waiting stage or the API returns `409`.

**Response 200**
```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "approved_stage": "SAST",
  "next_stage": "AI_HARNESS",
  "review_state": "approved"
}
```

**Response 409** when the job is not waiting for review.

---

### POST /api/jobs/{task_id}/review/retry

Discard the current stage and downstream review artifacts, then enqueue the same stage again.

**Request body**
```json
{
  "stage": "DAST"
}
```

`stage` is optional for older callers. When present, it must match the server-side waiting stage or the API returns `409`.

**Response 200**
```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "retry_stage": "DAST",
  "review_state": "retrying"
}
```

---

### POST /api/jobs/{task_id}/cancel

Mark an active job as cancelled, persist `FAILURE`, and best-effort cleanup runtime workspace and fuzzing image.

**Response 200**
```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "state": "FAILURE",
  "review_state": "cancelled"
}
```

---

## WebSocket

### WS /ws

Connect to receive real-time pipeline events for all active jobs.

**Connection:** `ws://<host>:8000/ws`  
**Protocol:** JSON text frames, server → client only (client messages are received but ignored)

---

### Pinned Event Schema

Every message is a JSON object. The base fields are always present; `vuln`, `result`, `fuzz_stats`, and `error_hint` are **absent** (not null) on standard events and only included on the specific events that carry them.

```json
{
  "task_id": "string",
  "step":    "INIT | SAST | AI_HARNESS | DAST | AI_PATCH | DB_STORAGE | ENV_GEN | PIPELINE",
  "status":  "Running | Success | Failed | Warning",
  "details": "string | null",
  "current_stage": "string | null",
  "review_state": "queued | running | waiting | approved | retrying | completed | failed | cancelled",
  "artifact": {},
  "compile_feedback": {
    "compile_attempt": 2,
    "max_attempts": 3,
    "stderr_excerpt": "compiler stderr excerpt",
    "llm_retry": true,
    "compiled": true
  },
  "severity": "High | Medium | Low",

  "error_hint": "string (actionable remediation hint; only on PIPELINE / Failed)",

  "vuln": {
    "message":      "string",
    "file":         "string",
    "code_snippet": "string | null"
  },

  "result": {
    "repo":             "string",
    "vuln_msg":         "string",
    "vuln_file":        "string",
    "patch_generated":  "boolean",
    "crash_hex":        "string | null",
    "patch_code":       "string | null"
  },

  "fuzz_stats": {
    "time_sec": "number",
    "execs":    "number",
    "crashes":  "number"
  }
}
```

---

### Step Lifecycle and Enriched Events

| Step | Statuses emitted | Enriched fields |
|------|-----------------|-----------------|
| `INIT` | Running | — |
| `SAST` | Running (streaming CodeQL output), **Success** | `vuln` on Success |
| `AI_HARNESS` | Running | — |
| `DAST` | Running (compile + poll every 10 s), Warning (compile retry), Success (compile, then crash found), Failed (compile exhausted or timeout) | `fuzz_stats` on each Running poll |
| `AI_PATCH` | Running, Success, Failed | — |
| `DB_STORAGE` | Running | — |
| `ENV_GEN` | Running, Success, Failed, Warning | — |
| `PIPELINE` | **Success**, **Failed** | `result` on Success; `error_hint` on Failed (when present) |

---

## Data Schemas

### JobRequest
```json
{ "repo_url": "string" }
```

### JobSummary
```json
{
  "task_id":      "string",
  "state":        "PENDING | STARTED | SUCCESS | FAILURE",
  "repo_url":     "string | null",
  "submitted_at": "ISO-8601 UTC string | null"
}
```

### VulnFinding
```json
{
  "message":      "string",
  "file":         "string (relative path from repo root)",
  "code_snippet": "string (first 500 chars of vulnerable file) | null"
}
```

### PipelineResult
```json
{
  "repo":            "string",
  "vuln_msg":        "string",
  "vuln_file":       "string",
  "patch_generated": "boolean",
  "crash_hex":       "string (hex-encoded AFL++ crash input) | null",
  "patch_code":      "string (LLM-generated patched C source) | null"
}
```

### JobStatusResponse
```json
{
  "task_id": "string",
  "state":   "PENDING | STARTED | SUCCESS | FAILURE",
  "vuln":    "VulnFinding | null",
  "result":  "PipelineResult | null"
}
```

### FuzzStats (WebSocket only)
```json
{
  "time_sec": "number (seconds since AFL++ started)",
  "execs":    "number (total executions)",
  "crashes":  "number (unique crashes found)"
}
```

---

## Error Responses

| Code | Condition |
|------|-----------|
| 400 | `POST /api/dev/llm-settings` — `model` not in the allow-list |
| 404 | `GET /api/jobs/{task_id}` — task_id not in job_store |
| 409 | `GET /api/jobs/{task_id}/report` — job not yet complete (`X-Job-State` header carries the state) |
| 422 | Malformed request body (FastAPI validation) |
| 503 | `POST /api/jobs` — Celery broker unavailable, job not queued |

---

## Dashboard Consumption Notes

The Project Dashboard (`/dashboard`) consumes **only the shared `/ws` transport** for real-time updates — it does not open a second WebSocket or poll the REST endpoints during a live run. The REST endpoints (`GET /api/jobs`, `GET /api/jobs/{task_id}`) are available for page-load hydration or job history display.

**Visualization library:** `recharts ^2.12.0` — `LineChart` for `fuzz_stats` (execs/crashes over time). Vulnerability details are rendered as Tailwind cards.

> **Prototype:** `frontend/src/ReviewGatePrototype.jsx` (route `/dev/review-gate`) is a
> **frontend-only design prototype** of a stage-gated review flow. It renders hardcoded mock
> data and has **no backend wiring** — it does not call any REST endpoint or open the `/ws`
> socket, and is not part of the live pipeline. Treat it as a UI mockup, not an API consumer.

---

## Report Endpoint

### GET /api/jobs/{task_id}/report

Returns the full vulnerability report for a completed job, including the SARIF taint-flow graph, the `main`→vulnerable-function call-reachability graph, and the original-vs-patch diff.

**Path parameter:** `task_id` — UUID returned from `POST /api/jobs`

**Response 200** — `ReportResponse`
```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "repo_url": "https://github.com/example/vulnerable-repo",
  "state": "SUCCESS",
  "vuln_summary": {
    "message": "Potential buffer overflow via strcpy",
    "file": "src/main.c",
    "rule_id": null
  },
  "taint_path": {
    "nodes": [
      { "id": "n0", "label": "input", "role": "source", "file": "src/main.c", "start_line": 5, "start_col": 1, "end_col": 10 },
      { "id": "n1", "label": "strcpy(buf, input)", "role": "sink", "file": "src/main.c", "start_line": 7, "start_col": 3, "end_col": 22 }
    ],
    "edges": [
      { "id": "e0", "source": "n0", "target": "n1" }
    ]
  },
  "call_path": {
    "nodes": [
      { "id": "call-0", "label": "main", "role": "source", "file": "src/main.c", "start_line": 7, "start_col": 0, "end_col": 0 },
      { "id": "call-1", "label": "vulnerable_func", "role": "sink", "file": "src/main.c", "start_line": 7, "start_col": 0, "end_col": 0 }
    ],
    "edges": [
      { "id": "call-edge-0-1", "source": "call-0", "target": "call-1" }
    ]
  },
  "diff": {
    "original": "void f(char* input) { char buf[10]; strcpy(buf, input); }",
    "patched":  "void f(char* input) { char buf[10]; strncpy(buf, input, 9); buf[9] = '\\0'; }",
    "language": "c"
  },
  "crash": { "hex": "4141414141414141414141" }
}
```

**Response 404** — job not found  
**Response 409** — job not yet complete; response header `X-Job-State` carries the current state (`PENDING | STARTED | FAILURE`)

---

## Developer Lab Endpoints

The Developer Lab (`frontend/src/DevLab.jsx`) lets a developer pick the Gemini model, supply
or clear an API key, toggle LLM-bypass (mock) mode, and choose a bundled sample repository —
all at runtime, without restarting the worker. Settings are stored in the Redis key
`dev:llm_config` and read by the Celery worker via `_get_dev_llm_config()` in `tasks.py`.

> **Security note:** the API key is write-only over this API. It is persisted in Redis but
> **never echoed back** — responses only report whether a key is set (`api_key_set`) and where
> it came from (`api_key_source`).

---

### GET /api/dev/options

Returns the available models, the current LLM settings, and the bundled sample repositories.

**Response 200** — `DevOptionsResponse`
```json
{
  "models": ["gemini-2.5-flash", "gemini-3-flash-preview", "gemini-3.5-flash"],
  "default_model": "gemini-2.5-flash",
  "llm": {
    "model": "gemini-2.5-flash",
    "api_key_set": true,
    "api_key_source": "dev",
    "bypass_llm": false
  },
  "sample_repos": [
    {
      "url": "sample://buffer-overflow",
      "name": "Buffer Overflow Sample",
      "description": "Tiny C project with argv/input taint reaching strcpy."
    }
  ]
}
```

`models` is the server-side allow-list (`ALLOWED_GEMINI_MODELS` in `tasks.py`). A
`sample_repos[].url` value can be submitted directly to `POST /api/jobs` as the `repo_url`.

---

### POST /api/dev/llm-settings

Updates the runtime LLM configuration. The chosen `model` must be in the allow-list.

**Request** — `DevLlmSettingsRequest`
```json
{
  "model": "gemini-2.5-flash",
  "api_key": "AIza...",
  "clear_api_key": false,
  "bypass_llm": false
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `model` | string | `gemini-2.5-flash` | Must be one of `ALLOWED_GEMINI_MODELS` |
| `api_key` | string\|null | `null` | New Gemini API key; stored in Redis (ignored when `clear_api_key` is true) |
| `clear_api_key` | boolean | `false` | Remove the stored dev API key (falls back to the `GEMINI_API_KEY` env var) |
| `bypass_llm` | boolean | `false` | Use mock fixture files instead of calling Gemini (see `DEBUG_BYPASS_LLM`) |

**Response 200** — `DevLlmSettingsResponse`
```json
{
  "model": "gemini-2.5-flash",
  "api_key_set": true,
  "api_key_source": "dev",
  "bypass_llm": false
}
```

`api_key_source` is `"dev"` when a key is stored in Redis, `"env"` when only the
`GEMINI_API_KEY` env var is set, or `null` when no key is available.

**Response 400** — `{ "detail": "Unsupported Gemini model" }` when `model` is not in the allow-list.

---

## Admin Endpoints

All admin endpoints read from PostgreSQL and reflect persisted state. They are independent of the in-memory `job_store` used by the real-time WebSocket layer.

---

### GET /admin/dashboard

Returns aggregate pipeline statistics and the 50 most recent jobs.

**Response 200** — `AdminDashboardResponse`
```json
{
  "total_jobs": 142,
  "pending":    3,
  "running":    1,
  "succeeded":  130,
  "failed":     8,
  "recent_jobs": [
    {
      "task_id":         "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "repo_url":        "https://github.com/example/repo",
      "submitted_by":    "user@example.com",
      "state":           "SUCCESS",
      "submitted_at":    "2026-05-31T12:00:00+00:00",
      "completed_at":    "2026-05-31T12:04:30+00:00",
      "patch_generated": true
    }
  ]
}
```

`recent_jobs` contains up to 50 entries, newest first. `submitted_by` is `null` for anonymous submissions.

---

### GET /admin/dashboard/jobs

Returns a paginated, filterable list of all jobs stored in PostgreSQL.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number (1-indexed) |
| `page_size` | int | 20 | Results per page (max 100) |
| `state` | string | — | Filter: `PENDING \| STARTED \| SUCCESS \| FAILURE` |
| `submitted_by` | string | — | Exact match on submitter identifier |
| `repo_url` | string | — | Case-insensitive substring match on repository URL |

**Response 200** — `AdminJobsListResponse`
```json
{
  "total":     142,
  "page":      1,
  "page_size": 20,
  "items": [ /* AdminJobSummary[] — same shape as recent_jobs above */ ]
}
```

---

### GET /admin/dashboard/jobs/{task_id}

Returns the full record for a single job, including the vulnerability finding and generated patch.

**Path parameter:** `task_id` — job UUID

**Response 200** — `AdminJobDetail`
```json
{
  "task_id":         "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "repo_url":        "https://github.com/example/repo",
  "submitted_by":    "user@example.com",
  "state":           "SUCCESS",
  "submitted_at":    "2026-05-31T12:00:00+00:00",
  "completed_at":    "2026-05-31T12:04:30+00:00",
  "vuln_message":    "Potential buffer overflow via strcpy",
  "vuln_file":       "src/main.c",
  "code_snippet":    "void vulnerable_func(char* input) { ... }",
  "patch_generated": true,
  "crash_hex":       "4141414141414141414141",
  "patch_code":      "void vulnerable_func(char* input) { ... }"
}
```

`vuln_message`, `vuln_file`, `code_snippet`, `patch_generated`, `crash_hex`, and `patch_code` are `null` until the corresponding pipeline steps complete.

**Response 404** — job not found

---

### GET /admin/dashboard/users

Returns per-user job statistics, ordered by most recent activity. Anonymous submissions (`submitted_by = null`) are grouped as a single entry.

**Response 200** — `AdminUsersResponse`
```json
{
  "items": [
    {
      "submitted_by":      "user@example.com",
      "total_jobs":        25,
      "succeeded":         22,
      "failed":            3,
      "last_submitted_at": "2026-05-31T12:00:00+00:00"
    },
    {
      "submitted_by":      null,
      "total_jobs":        12,
      "succeeded":         10,
      "failed":            2,
      "last_submitted_at": "2026-05-30T09:15:00+00:00"
    }
  ]
}
```

---

## Admin Data Schemas

### AdminJobSummary
```json
{
  "task_id":         "string",
  "repo_url":        "string",
  "submitted_by":    "string | null",
  "state":           "PENDING | STARTED | SUCCESS | FAILURE",
  "submitted_at":    "ISO-8601 UTC datetime",
  "completed_at":    "ISO-8601 UTC datetime | null",
  "patch_generated": "boolean | null"
}
```

### AdminJobDetail
All fields from `AdminJobSummary`, plus:
```json
{
  "vuln_message":    "string | null",
  "vuln_file":       "string | null",
  "code_snippet":    "string | null",
  "crash_hex":       "string | null",
  "patch_code":      "string | null"
}
```

### UserStats
```json
{
  "submitted_by":      "string | null",
  "total_jobs":        "integer",
  "succeeded":         "integer",
  "failed":            "integer",
  "last_submitted_at": "ISO-8601 UTC datetime"
}
```

### ReportResponse
```json
{
  "task_id":     "string",
  "repo_url":    "string",
  "state":       "string",
  "vuln_summary": { "message": "string|null", "file": "string|null", "rule_id": "string|null" },
  "taint_path":  { "nodes": "TaintNode[]", "edges": "TaintEdge[]" },
  "call_path":   { "nodes": "TaintNode[]", "edges": "TaintEdge[]" },
  "diff":        { "original": "string", "patched": "string", "language": "string" },
  "crash":       { "hex": "string | null" }
}
```

**TaintNode:** `{ id, label, role, file, start_line, start_col, end_col }`  
**TaintEdge:** `{ id, source, target }`  
`taint_path` is the CodeQL source→sink data-flow path (roles: `source`/`intermediate`/`sink`).
`call_path` is the static call-reachability chain from `main` to the vulnerable function
(same node/edge shape; roles map `source`=entry `main`, `intermediate`=caller, `sink`=vulnerable fn).
Both default to `{ "nodes": [], "edges": [] }` when unavailable.
`diff.language` is inferred from `vuln_file` extension: `c`, `cpp`, or `plaintext`.

---

## Environment Variables

The core service variables are listed in the root `CLAUDE.md`. The following additional
variables are read by the worker but were not previously documented:

| Variable | Read in | Default | Purpose |
|----------|---------|---------|---------|
| `GEMINI_MODEL` | `tasks.py`, `main.py` | `gemini-2.5-flash` | Fallback Gemini model when no dev config is stored; must be in `ALLOWED_GEMINI_MODELS` |
| `CODEQL_THREADS` | `tasks.py` | `1` | `--threads` passed to `codeql database analyze` |
| `CODEQL_RAM_MB` | `tasks.py` | `2048` | `--ram` (MB) passed to `codeql database analyze` |
| `TCPDUMP_FUZZ_TIMEOUT` | `debug_tcpdump.py` | `90` | Seconds per fuzzing attempt in `DEBUG_TEST_TCPDUMP` resilience mode |
| `TCPDUMP_FUZZ_ATTEMPTS` | `debug_tcpdump.py` | `6` | Number of fuzzing attempts in `DEBUG_TEST_TCPDUMP` resilience mode |

See `docs/sast-analysis.md` and `docs/dynamic-analysis.md` for how these are used.
