# Backend Development Guide

## API & WebSocket Reference

Always consult these before adding or changing endpoints or event shapes:

| Document | Covers |
|----------|--------|
| `docs/api-spec.md` | All REST, Developer Lab, and admin endpoint contracts, schemas, error codes, env vars |
| `docs/websocket.md` | WebSocket event schema, step lifecycle, server architecture |
| `docs/sast-analysis.md` | SAST stage: CodeQL two-pass analysis, query packs, taint/call-path graphs |
| `docs/dynamic-analysis.md` | AI_HARNESS + DAST + ENV_GEN: harness generation, Docker env build, AFL++ fuzzing, `sample://` protocol |
| `docs/auto-remediation.md` | AI_PATCH stage: patch generation, persistence, report rendering |

## Key Rules

- **Keep `main.py` thin.** HTTP endpoint definitions and the WebSocket relay only. All pipeline logic belongs in `tasks.py`.
- **Publish via `notify_status()`.** Use the existing helper in `tasks.py` for all pipeline progress events — never write to the WebSocket directly from a Celery worker (different process, no access to `ConnectionManager`).
- **Domain terminology:** use `"job"` in all API responses and log messages. Never `"task"` (Celery's internal term) or `"scan"`.
- **Don't break existing contracts.** `/api/jobs` and `/ws` shapes are consumed by the frontend — do not alter them without explicit permission. Update `docs/api-spec.md` when adding new endpoints.

## WebSocket Publish Path

```
tasks.py: notify_status()
    → Redis PubSub "pipeline_logs"
    → main.py: redis_listener()
    → ConnectionManager.broadcast()
    → /ws clients
```

See `docs/websocket.md` for the full event schema and step lifecycle.

## Adding Endpoints

1. Define Pydantic request/response schemas near the top of `main.py` (follow the pattern at lines 31–184).
2. Add the route function.
3. Update `docs/api-spec.md` with the new endpoint contract (request, response, error codes).

## Testing & Formatting

- Place `test_*.py` files next to the module they test (e.g., `backend/test_main.py`).
- Run `black .` before committing — it must report no changes.
- Run `pytest` if tests exist.
