# Frontend Development Guide

## API & WebSocket Reference

Always consult these before changing how the UI communicates with the backend:

| Document | Covers |
|----------|--------|
| `docs/api-spec.md` | All REST and admin endpoint contracts, schemas, error codes |
| `docs/websocket.md` | WebSocket event schema, step lifecycle, frontend integration notes |

## Key Rules

- **Domain terminology:** use `"job"` in all UI labels and copy. Never `"task"` or `"scan"`.
- **One WebSocket connection.** `Dashboard.jsx` opens a single `/ws` connection on mount. Do not open a second connection for new jobs — pass event data down as props instead.
- **No polling during live runs.** All real-time state (node colours, live logs, fuzzer charts) comes from the WebSocket. REST endpoints are for page-load hydration and job history only.
- **Naming:** `PascalCase` for component filenames and function names; `camelCase` for variables, handlers, and props.

## WebSocket Client Pattern

URL construction (auto-detects HTTP vs HTTPS):

```javascript
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.hostname}:8000/ws`;
const ws = new WebSocket(wsUrl);
```

Every message is a JSON object. Base fields (`task_id`, `step`, `status`, `details`) are always present. Check for optional fields by key presence, not null:

```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if ('vuln' in data)       { /* SAST result */ }
  if ('result' in data)     { /* final pipeline result */ }
  if ('fuzz_stats' in data) { /* AFL++ poll update */ }
};
```

See `docs/websocket.md` for the full step lifecycle and enriched-field rules.

## Adding New Components

- Place in `frontend/src/`.
- If a component needs pipeline events, wire it through `Dashboard.jsx`'s existing WebSocket — pass data down as props.
- Register new pages in `frontend/src/main.jsx` (React Router).
