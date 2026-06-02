# WebSocket Reference

**Endpoint:** `WS /ws`  
**Base URL:** `ws://<host>:8000/ws` (use `wss:` when served over HTTPS)  
**Protocol:** JSON text frames, server → client only (client messages are received but ignored)

---

## Server Architecture

Pipeline progress flows through three layers before reaching the browser:

```
tasks.py: notify_status()
    │  publishes JSON to Redis PubSub channel "pipeline_logs"
    ▼
main.py: redis_listener()          ← started as an asyncio task on app startup
    │  decodes each message, updates job_store and PostgreSQL
    ▼
main.py: ConnectionManager.broadcast()
    │  sends the raw JSON string to every active WebSocket connection
    ▼
Browser: ws.onmessage handler
```

**Key source locations:**

| Component | File | Lines |
|-----------|------|-------|
| `notify_status()` publisher | `backend/tasks.py` | 27–41 |
| `ConnectionManager` class | `backend/main.py` | 193–211 |
| `redis_listener()` async loop | `backend/main.py` | 281–305 |
| `/ws` FastAPI endpoint | `backend/main.py` | 615–623 |
| WebSocket client (frontend) | `frontend/src/Dashboard.jsx` | 52–102 |

---

## Event Schema

Every message is a UTF-8 JSON object. **Base fields are always present.** Optional fields (`vuln`, `result`, `fuzz_stats`, `error_hint`) are **absent** (not `null`) on events that do not carry them — check with `"vuln" in data`, not `data.vuln !== null`.

```json
{
  "task_id": "string (UUID)",
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
    "file":         "string (relative path from repo root)",
    "code_snippet": "string (first 500 chars of vulnerable file) | null"
  },

  "result": {
    "repo":            "string",
    "vuln_msg":        "string",
    "vuln_file":       "string",
    "patch_generated": "boolean",
    "crash_hex":       "string (hex-encoded AFL++ crash input) | null",
    "patch_code":      "string (LLM-generated patched C source) | null"
  },

  "fuzz_stats": {
    "time_sec": "number (seconds since AFL++ started)",
    "execs":    "number (total executions)",
    "crashes":  "number (unique crashes found)"
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | string | UUID of the job, matches the value from `POST /api/jobs` |
| `step` | string | Pipeline stage that emitted this event |
| `status` | string | Current status of that step |
| `details` | string\|null | Human-readable progress message or error detail |
| `current_stage` | string\|null | Present in review mode when a stage task changes or waits |
| `review_state` | string\|null | Review-mode gate state |
| `artifact` | object | Reviewable stage output for the dashboard |
| `compile_feedback` | object | DAST harness compile feedback-loop state |
| `severity` | string | SAST severity shown in the dashboard risk summary |
| `vuln` | object | Only present on `SAST / Success` — CodeQL finding |
| `result` | object | Only present on `PIPELINE / Success` — final pipeline result |
| `fuzz_stats` | object | Only present on `DAST / Running` polling events |
| `error_hint` | string | Only present on `PIPELINE / Failed` when the failure was a `PipelineUserError` — an actionable remediation hint (e.g. "Lower CODEQL_RAM_MB…"). May be `null` if the error carried no hint. The dashboard renders it alongside the error detail. |

---

## Step Lifecycle

| Step | Statuses emitted | Enriched fields | Notes |
|------|-----------------|-----------------|-------|
| `INIT` | Running | — | Job acknowledged, pipeline starting |
| `SAST` | Running, **Success**, Failed | `vuln` on Success | Streams CodeQL output; `vuln` carries the taint finding |
| `AI_HARNESS` | Running | — | LLM generates the AFL++ persistent-mode harness |
| `DAST` | Running, Warning, Success, Failed | `fuzz_stats` on each Running poll | Covers both **compile** and **fuzz**: Warning on each failed compile (up to 3 LLM-feedback retries; compiler stderr fed back to LLM), Success on compile and again when AFL++ finds a crash, Failed on compile exhaustion or fuzz timeout. `fuzz_stats` accompanies each 10 s poll. See `docs/dynamic-analysis.md` |
| `AI_PATCH` | Running, Success, Failed | — | LLM generates the patch |
| `DB_STORAGE` | Running | — | Persisting results to PostgreSQL |
| `ENV_GEN` | Running, Success, Failed, Warning | — | Docker image build for the fuzzing environment |
| `PIPELINE` | **Success**, **Failed** | `result` on Success; `error_hint` on Failed | Terminal event. `result` carries the full outcome on success; on a `PipelineUserError` failure, `error_hint` carries a remediation hint |

---

## Backend Implementation Notes

### ConnectionManager (`main.py:193–211`)

```python
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        await asyncio.gather(
            *[conn.send_text(message) for conn in self.active_connections],
            return_exceptions=True,   # one broken connection doesn't stop others
        )
```

`broadcast()` uses `return_exceptions=True` so a broken client socket does not abort delivery to healthy connections.

### redis_listener() (`main.py:281–305`)

Started as an `asyncio.create_task()` inside the `startup_event` handler. It:
1. Subscribes to the `"pipeline_logs"` Redis PubSub channel.
2. For each message: decodes the JSON, calls `_update_job_store()` (in-memory) and `_db_sync_update()` (PostgreSQL, via thread pool executor), then calls `manager.broadcast(raw)`.
3. On error: sleeps 2 s, resubscribes — the loop is self-healing.

### Publishing from tasks (`tasks.py:notify_status()`)

All pipeline status updates must go through `notify_status()` in `tasks.py`. **Never write to the WebSocket directly from a Celery worker** — workers run in a separate process and have no reference to the FastAPI WebSocket connections.

---

## Frontend Integration Notes

### URL Construction (`Dashboard.jsx:52–55`)

```javascript
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsHost = window.location.hostname;
const wsUrl = `${wsProtocol}//${wsHost}:8000/ws`;
const ws = new WebSocket(wsUrl);
```

The port is always `8000` (backend). This snippet handles HTTP/HTTPS automatically.

### Message Handler (`Dashboard.jsx:57–100`)

```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // data.task_id, data.step, data.status, data.details always present
  // data.vuln        — check with "vuln" in data
  // data.result      — check with "result" in data
  // data.fuzz_stats  — check with "fuzz_stats" in data
};
```

### Conventions

- The dashboard opens **one** WebSocket connection on mount and keeps it for the lifetime of the page — do not open a second connection for new jobs.
- All real-time state (node colours, live logs, charts) is driven exclusively by WebSocket events during a live run. REST endpoints are for page-load hydration only.
- `fuzz_stats` events accumulate into an array and are fed to the `recharts` `<LineChart>` as `{ time_sec, execs, crashes }` data points.

### Review-Mode Dashboard

When `POST /api/jobs` is submitted with `review_mode=true`, the Project Dashboard still uses the same `/ws` connection. Stage tasks emit the normal base fields plus review metadata:

- `SAST`, `AI_HARNESS`, `DAST`, and `AI_PATCH` emit `review_state="waiting"` with an `artifact`.
- `DAST` compile attempts emit `compile_feedback` so the dashboard can display the self-healing stderr reinjection loop.
- `PIPELINE / Success` still carries `result`; the dashboard links to `/report/{task_id}` after completion.

Review actions are HTTP calls, not WebSocket messages:

- `POST /api/jobs/{task_id}/review/approve`
- `POST /api/jobs/{task_id}/review/retry`
- `POST /api/jobs/{task_id}/cancel`
