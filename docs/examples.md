# Examples

Copy-pasteable, runnable snippets. They assume the stack is up (see
[getting-started.md](getting-started.md)) with the API on `http://localhost:8000`. Full
contracts are in [api-spec.md](api-spec.md) and [websocket.md](websocket.md).

## Submit a job — GitHub repo

```bash
curl -s -X POST http://localhost:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{
        "repo_url": "https://github.com/owner/repo",
        "submitted_by": "you@example.com"
      }'
# -> {"message":"Job submitted successfully","task_id":"<uuid>"}
```

## Submit a job — built-in sample (fastest, no network)

```bash
curl -s -X POST http://localhost:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{"repo_url": "sample://buffer-overflow", "submitted_by": "you@example.com"}'
```

## Submit a job — inline source

```bash
curl -s -X POST http://localhost:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{
        "target_type": "source",
        "source_code": "#include <string.h>\nvoid f(char*s){char b[8];strcpy(b,s);}\nint main(int c,char**v){f(v[1]);return 0;}"
      }'
```

## Submit a job — review mode (human-gated)

```bash
# 1. start in review mode
TASK=$(curl -s -X POST http://localhost:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{"repo_url":"sample://buffer-overflow","review_mode":true}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["task_id"])')

# 2. when review_state == "waiting", approve the current stage to advance
curl -s -X POST http://localhost:8000/api/jobs/$TASK/review/approve \
  -H 'Content-Type: application/json' -d '{"stage":"SAST"}'

# 3. or retry the current stage instead (clears downstream results)
curl -s -X POST http://localhost:8000/api/jobs/$TASK/review/retry \
  -H 'Content-Type: application/json' -d '{"stage":"SAST"}'
```

## Poll status

```bash
curl -s http://localhost:8000/api/jobs/<uuid> | python -m json.tool
# state goes PENDING -> STARTED -> SUCCESS (or FAILURE; read failure_detail)
```

## Fetch the report (after SUCCESS)

```bash
curl -s http://localhost:8000/api/jobs/<uuid>/report | python -m json.tool
# 200 with {vuln_summary, taint_path, call_path, diff, crash} once state == SUCCESS
# 409 with an X-Job-State header while the job is still running
```

## Cancel a job

```bash
curl -s -X POST http://localhost:8000/api/jobs/<uuid>/cancel
```

## Listen to live pipeline events (WebSocket)

```python
# pip install websocket-client
import json, websocket

TASK = "<uuid>"
ws = websocket.create_connection("ws://localhost:8000/ws")
try:
    while True:
        evt = json.loads(ws.recv())
        if evt.get("task_id") != TASK:
            continue  # the /ws stream is global; filter by your task_id
        print(evt["step"], evt["status"], "-", evt.get("details", ""))
        if evt["step"] == "PIPELINE" and evt["status"] in ("Success", "Failed"):
            break
finally:
    ws.close()
```

Browser equivalent (what `Dashboard.jsx` does):

```js
const proto = location.protocol === "https:" ? "wss:" : "ws:";
const ws = new WebSocket(`${proto}//${location.hostname}:8000/ws`);
ws.onmessage = (e) => {
  const evt = JSON.parse(e.data);
  if (evt.task_id !== currentTaskId) return;
  // render evt.step / evt.status / evt.details ...
};
```

## Developer Lab — read & change LLM settings

```bash
# what's available (models, current LLM config, sample repos)
curl -s http://localhost:8000/api/dev/options | python -m json.tool

# switch model / set a per-runtime API key (stored in Redis dev:llm_config)
curl -s -X POST http://localhost:8000/api/dev/llm-settings \
  -H 'Content-Type: application/json' \
  -d '{"model":"gemini-2.5-flash","bypass_llm":false}'
```

## Admin dashboard queries

```bash
curl -s http://localhost:8000/admin/dashboard | python -m json.tool
curl -s "http://localhost:8000/admin/dashboard/jobs?state=SUCCESS&page=1&page_size=20" | python -m json.tool
curl -s http://localhost:8000/admin/dashboard/users | python -m json.tool
```

## Standalone CLI

```bash
source .venv/bin/activate
GEMINI_API_KEY=<key> python pipeline.py https://github.com/owner/repo --branch main
# writes vulnerability_report.json
```
