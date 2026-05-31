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
  "repo_url": "https://github.com/example/vulnerable-repo"
}
```

**Response 200**
```json
{
  "message": "Job submitted successfully",
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

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

## WebSocket

### WS /ws

Connect to receive real-time pipeline events for all active jobs.

**Connection:** `ws://<host>:8000/ws`  
**Protocol:** JSON text frames, server → client only (client messages are received but ignored)

---

### Pinned Event Schema

Every message is a JSON object. The base fields are always present; `vuln`, `result`, and `fuzz_stats` are **absent** (not null) on standard events and only included on the specific events that carry them.

```json
{
  "task_id": "string",
  "step":    "INIT | SAST | AI_HARNESS | DAST | AI_PATCH | DB_STORAGE | ENV_GEN | PIPELINE",
  "status":  "Running | Success | Failed | Warning",
  "details": "string | null",

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
| `AI_HARNESS` | Running, Success, Warning (compile retry) | — |
| `DAST` | Running (poll every 10 s), Success (crash found), Failed | `fuzz_stats` on each Running poll |
| `AI_PATCH` | Running, Success, Failed | — |
| `DB_STORAGE` | Running | — |
| `ENV_GEN` | Running, Success, Failed, Warning | — |
| `PIPELINE` | **Success**, **Failed** | `result` on Success |

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
| 404 | `GET /api/jobs/{task_id}` — task_id not in job_store |
| 422 | Malformed request body (FastAPI validation) |

---

## Dashboard Consumption Notes

The Project Dashboard (`/dashboard`) consumes **only the shared `/ws` transport** for real-time updates — it does not open a second WebSocket or poll the REST endpoints during a live run. The REST endpoints (`GET /api/jobs`, `GET /api/jobs/{task_id}`) are available for page-load hydration or job history display.

**Visualization library:** `recharts ^2.12.0` — `LineChart` for `fuzz_stats` (execs/crashes over time). Vulnerability details are rendered as Tailwind cards.
