# Contributing to SmartFuzzQL (HAST)

Thanks for working on SmartFuzzQL. This guide covers the dev environment, tests, code style, and
the conventions that keep the codebase coherent. For *how the system works*, start with
[docs/architecture.md](docs/architecture.md); for the docs map, see [docs/README.md](docs/README.md).

## Dev environment

The full stack runs under Docker Compose:

```bash
GEMINI_API_KEY=<key> docker-compose up --build   # web :8000, frontend :5173, redis, db, worker
```

For focused backend or frontend work you can run pieces directly:

```bash
# backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000                       # API
celery -A tasks.celery_app worker --loglevel=info           # worker (needs Redis + Docker)
DEBUG_BYPASS_LLM=True celery -A tasks.celery_app worker ...  # worker without a Gemini key

# frontend
cd frontend
npm install
npm run dev      # http://localhost:5173
npm run build    # production build
```

You still need Redis and Postgres reachable for the backend (the Compose `redis`/`db` services
are the easy way). See [docs/configuration.md](docs/configuration.md) for every env var, and
[docs/getting-started.md](docs/getting-started.md) for a first run.

## Tests

Backend tests use `pytest` and live **next to the module they test** (e.g. `backend/test_tasks.py`,
`backend/test_review_mode.py`).

```bash
cd backend
pytest
```

Most tests are designed to run **without Docker, Joern, or a Gemini key** — e.g. the SARIF→graph
parsers and the Joern→SARIF adapter are tested against fixtures. Keep new tests that way where
possible; gate anything needing Docker/network behind an explicit marker or skip.

When you add a feature, add a test next to its module. When you change a pipeline stage, cover the
review-mode counterpart too.

## Code style

| Area | Tool | Rule |
|------|------|------|
| Backend (Python) | `black` | Run `black .` before committing — it must report **no changes**. `snake_case` functions/vars, `PascalCase` classes. |
| Frontend (JS/JSX) | `eslint` | `npm run lint`. `PascalCase` components, `camelCase` vars/handlers. |

> **Keep diffs focused.** Don't run `black` (or a formatter) across whole untouched files — format
> only the lines you changed so reviews stay readable.

## Architectural rules (don't break these)

- **`main.py` stays thin.** HTTP endpoints and the WebSocket relay only. All pipeline/LLM logic
  lives in `tasks.py` (or shared modules like `patching.py`, `joern_analysis.py`).
- **Publish progress via `notify_status()`** in `tasks.py` — never write to `/ws` from a worker.
- **One LLM SDK.** All model calls go through `call_llm_api` (`google-genai`). Don't add another.
- **Domain terminology:** always `"job"` in API responses, UI, and logs — never `"task"`
  (Celery's term) or `"scan"`.
- **Stable contracts.** Don't change the shape of `/api/jobs` or `/ws` without explicit sign-off —
  the frontend depends on them. When you add/alter an endpoint, update
  [docs/api-spec.md](docs/api-spec.md); for events, [docs/websocket.md](docs/websocket.md).
- **Docker template:** don't alter the structure of `backend/Dockerfile.template`; the
  `{{ TARGET_DEPS }}` placeholder is required for per-job dependency injection.
- **No credentials in git.** `GEMINI_API_KEY` and friends come from env/`.env` only.
- When readability and performance conflict, prefer readability.

## Documentation

Any change that touches a contract or a stage must update the matching doc under `docs/`
(see the table in [CLAUDE.md](CLAUDE.md)). New design decisions get an
[ADR](docs/adr/README.md).

## Branches, commits, PRs

- Branch off `main`; don't commit directly to `main`.
- Commit messages follow the existing `type(scope): summary` convention seen in the history
  (`feat(sast): …`, `fix(ws): …`, `docs: …`).
- **Do not add a `Co-Authored-By` trailer** to commits.
- Open a PR against `main`. Before requesting review: `black .` clean, `pytest` green, `npm run
  lint` clean, and the relevant `docs/` updated. Note any user-visible change in
  [CHANGELOG.md](CHANGELOG.md) under `Unreleased`.

## Reporting security issues

If you find a vulnerability **in SmartFuzzQL itself**, follow [SECURITY.md](SECURITY.md) — do not
open a public issue.
