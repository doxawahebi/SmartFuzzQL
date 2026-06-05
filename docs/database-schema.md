# Database Schema

This document is the developer reference for SmartFuzzQL (HAST)'s database: what is stored,
where, and how to inspect it. For API response shapes built **from** this data, see
[`api-spec.md`](./api-spec.md).

**Source of truth:** the schema is defined in code, not in migrations.

| Concern | File |
|---------|------|
| Table / column definitions (ORM) | `backend/models.py` |
| Engine, session, and schema bootstrap | `backend/database.py` |

---

## Overview

- **Engine:** PostgreSQL 15 (`postgres:15-alpine`), run as the `db` service in
  `docker-compose.yml` (database `hast_db`, default user/password, port 5432, persisted in the
  `postgres_data` volume).
- **ORM:** SQLAlchemy declarative base.
- **Tables:** exactly one — **`jobs`**. One row per pipeline run (a "job").
- **Migrations:** **none (no Alembic).** The schema is created and evolved at app startup by
  `init_db()` — see [Schema bootstrap & evolution](#schema-bootstrap--evolution).

---

## Connection & configuration

Defined in `backend/database.py`:

```python
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://user:password@db:5432/hast_db"
)
engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()
```

- `DATABASE_URL` — connection string. The default targets the docker-compose `db` host.
  In `docker-compose.yml` both the `web` and `worker` services set it explicitly.
- `pool_pre_ping=True` — discards stale connections before reuse.
- **`get_db()`** — FastAPI dependency that yields a request-scoped session and closes it after
  the request. Used by HTTP route handlers in `backend/main.py`.
- **`SessionLocal()`** — instantiated directly inside Celery workers (`backend/tasks.py`), which
  run in a separate process and cannot use FastAPI's dependency injection.

### Schema bootstrap & evolution

`init_db()` is called once at app startup. It does two things:

1. `Base.metadata.create_all(bind=engine)` — creates the `jobs` table from the ORM model if it
   does not already exist.
2. Runs a list of `ALTER TABLE jobs ADD COLUMN IF NOT EXISTS <col> <type>` statements for
   columns added after the table's original shape. This is an idempotent, Alembic-free way to
   roll new columns onto an existing database without dropping data.

**Adding a new column** is therefore a two-step change — keep them in sync:

1. Add the `Column(...)` to the `Job` model in `backend/models.py`.
2. Add a matching `("<col>", "<SQL TYPE>")` entry to the `ALTER TABLE` list in
   `backend/database.py` so existing deployments pick it up on next startup.

> SQLAlchemy's `JSON` columns map to PostgreSQL `JSONB`.

---

## The `jobs` table

One row per pipeline run. Columns grouped by purpose below; all of them live in a single flat
table.

### Identity & lifecycle

| Column | Type | Null | Default | Notes |
|--------|------|------|---------|-------|
| `id` | Integer | no | auto | Primary key, indexed. Surrogate auto-increment. |
| `task_id` | String(36) | no | — | **Unique, indexed.** Job UUID (the Celery task id). Used everywhere as the public job identifier. |
| `repo_url` | Text | no | — | GitHub repo URL, or `inline://{task_id}` for inline source submissions. |
| `submitted_by` | String(255) | yes | NULL | Indexed. Submitter email/identifier, for admin reporting. |
| `state` | String(20) | no | `"PENDING"` | Job lifecycle state. See [Enumerated values](#enumerated-values). |
| `submitted_at` | DateTime | no | `utcnow()` | UTC submission timestamp. |
| `completed_at` | DateTime | yes | NULL | UTC timestamp set when the job reaches `SUCCESS`/`FAILURE`. |
| `failure_detail` | Text | yes | NULL | Error message when `state = FAILURE`. |
| `target_type` | String(20) | no | `"repo"` | `"repo"` or `"source"` (inline C/C++). |

### SAST results

| Column | Type | Null | Default | Notes |
|--------|------|------|---------|-------|
| `vuln_message` | Text | yes | NULL | Vulnerability description from the SAST stage. |
| `vuln_file` | Text | yes | NULL | Relative path of the vulnerable file. |
| `code_snippet` | Text | yes | NULL | Short excerpt of the vulnerable source. |
| `original_code` | Text | yes | NULL | Full original vulnerable source code. |
| `taint_path` | JSON | yes | NULL | SARIF taint-flow graph. See [JSON column shapes](#json-column-shapes). |
| `call_path` | JSON | yes | NULL | Call-reachability graph (entry → vulnerable function). |

### DAST & patch results

| Column | Type | Null | Default | Notes |
|--------|------|------|---------|-------|
| `crash_hex` | Text | yes | NULL | AFL++ crash input as a hex string. |
| `patch_generated` | Boolean | yes | NULL | `True` if a patch was produced. |
| `patch_code` | Text | yes | NULL | LLM-generated patch source. |

### Review-mode fields

These are populated only when a job runs in stage-gated review mode.

| Column | Type | Null | Default | Notes |
|--------|------|------|---------|-------|
| `review_mode` | Boolean | no | `False` | `True` for stage-gated runs. |
| `workspace_path` | Text | yes | NULL | Filesystem path to the review workspace (e.g. `/tmp/{task_id}/`). |
| `current_stage` | String(40) | yes | NULL | Stage currently executing or awaiting review. |
| `review_state` | String(40) | yes | NULL | Review status. See [Enumerated values](#enumerated-values). |
| `stage_results` | JSON | yes | NULL | Per-stage result payloads (lower-case keys). |
| `stage_artifacts` | JSON | yes | NULL | Per-stage artifacts (UPPER-case keys). |

### Indexes

- `id` — primary key.
- `task_id` — unique index (primary lookup key).
- `submitted_by` — index (admin filtering by user).

---

## Enumerated values

These are stored as plain strings (no DB-level `ENUM` type); the allowed values are enforced in
application code.

**`state`** — overall job lifecycle:

| Value | Meaning |
|-------|---------|
| `PENDING` | Queued, not yet started. |
| `STARTED` | Pipeline running. |
| `SUCCESS` | Pipeline completed. |
| `FAILURE` | Pipeline failed or was cancelled (see `failure_detail`). |

**`review_state`** — set only when `review_mode = true`:

| Value | Meaning |
|-------|---------|
| `queued` | Enqueued, waiting to enter the first stage. |
| `running` | A stage is currently executing. |
| `waiting` | Stage finished; paused for human review before continuing. |
| `approved` | Human approved the stage; next stage enqueued. |
| `retrying` | Human re-ran the stage; downstream results cleared. |
| `cancelled` | User cancelled the job. |

**`current_stage`** — pipeline stage names: `INIT`, `SAST`, `AI_HARNESS`, `DAST`, `AI_PATCH`,
`REPORT`, `DB_STORAGE`.

**`target_type`** — `repo` (clone a GitHub repo) or `source` (inline C/C++ submission).

---

## JSON column shapes

`taint_path` and `call_path` are graphs consumed by the React Flow viewer:

```jsonc
{
  "nodes": [
    { "id": "n0", "label": "...", "role": "source",
      "file": "src/foo.c", "start_line": 12, "start_col": 3, "end_col": 18 }
  ],
  "edges": [
    { "id": "e0", "source": "n0", "target": "n1" }
  ]
}
```

`stage_results` and `stage_artifacts` are dictionaries keyed by stage. **Mind the casing:**

- `stage_results` uses **lower-case** stage keys: `{ "sast": {...}, "harness": {...}, "dast": {...}, "patch": {...} }`
- `stage_artifacts` uses **UPPER-case** stage keys: `{ "SAST": {...}, "AI_HARNESS": {...}, "DAST": {...}, "AI_PATCH": {...} }`

---

## How to read the DB

### With `psql`

Open a shell against the running container:

```bash
docker-compose exec db psql -U user -d hast_db
```

Useful commands once inside:

```sql
\dt                 -- list tables (expect: jobs)
\d jobs             -- describe columns, types, indexes

-- Most recent jobs
SELECT task_id, state, repo_url, submitted_at
FROM jobs
ORDER BY submitted_at DESC
LIMIT 5;

-- Jobs by state
SELECT state, count(*) FROM jobs GROUP BY state;

-- One job by id
SELECT * FROM jobs WHERE task_id = '<uuid>';

-- Pretty-print a JSON column
SELECT jsonb_pretty(taint_path) FROM jobs WHERE task_id = '<uuid>';
```

### Through the ORM (Python shell)

From the `backend/` directory, with `DATABASE_URL` pointing at the database:

```python
from database import SessionLocal
from models import Job

db = SessionLocal()
job = db.query(Job).filter(Job.task_id == "<uuid>").first()
print(job.state, job.vuln_file, job.patch_generated)
print(job.taint_path)   # already deserialized to a dict
db.close()
```

### Where the app reads & writes rows

Understanding the lifecycle of a row helps when debugging stale or missing data:

| Action | Where |
|--------|-------|
| Insert a new job on submission | `backend/main.py` (job submission handler) |
| Sync state/results from pipeline events | `_db_sync_update()` in `backend/main.py` |
| Admin list / filter / counts | grouped & filtered `db.query(Job)` calls in `backend/main.py` |
| Worker writes final SAST/DAST/patch results | `_store_db_results()` in `backend/tasks.py` |
| Worker marks a failure | `_mark_pipeline_failed()` in `backend/tasks.py` |
| Worker updates review-mode stage state | `_set_review_job()` / `_merge_review_payload()` in `backend/tasks.py` |

---

## See also

- [`api-spec.md`](./api-spec.md) — REST/admin response schemas built from these columns.
- [`sast-analysis.md`](./sast-analysis.md) — how `taint_path` / `call_path` are produced.
- [`auto-remediation.md`](./auto-remediation.md) — how `patch_code` / `patch_generated` are produced and persisted.
