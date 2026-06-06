# Changelog

All notable changes to SmartFuzzQL (HAST) are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project has not yet cut a
versioned release, so everything to date sits under **Unreleased**.

## Compatibility & deprecation policy

- **Stable contracts.** `POST /api/jobs` and the `/ws` event stream are consumed by the frontend
  and are treated as stable. Breaking changes to their shapes require explicit sign-off and a note
  in this changelog.
- **Reference is authoritative.** [docs/api-spec.md](docs/api-spec.md),
  [docs/websocket.md](docs/websocket.md), and [docs/database-schema.md](docs/database-schema.md)
  describe the current contracts. When a contract changes, those docs change in the same PR.
- **Deprecations.** When an endpoint, field, or env var is slated for removal, it will be marked
  *Deprecated* here (and in the relevant reference doc) for at least one release before removal,
  with the replacement named.
- **Schema evolution.** The `jobs` table is created/altered by `init_db()` on web startup; there
  is no migration tool yet. Column additions are backward-compatible; document any removal here.

---

## [Unreleased]

### Added
- **Documentation set.** Developer docs reorganised around Diátaxis: a docs index
  ([docs/README.md](docs/README.md)), [getting-started](docs/getting-started.md),
  [architecture](docs/architecture.md) + [ADRs](docs/adr/README.md),
  [configuration](docs/configuration.md), [how-to](docs/how-to.md), [examples](docs/examples.md),
  [operations](docs/operations.md) with an error catalog, plus glossary, FAQ, `CONTRIBUTING.md`,
  `SECURITY.md`, and this changelog.
- **Joern build-free SAST fallback.** When CodeQL can't build or finds nothing, Joern extracts an
  AST/CFG/CPG from source and its output is adapted to CodeQL-shaped SARIF, so the pipeline no
  longer aborts at SAST. Toggled by `JOERN_FALLBACK` / `JOERN_FORCE`.
  ([ADR-0001](docs/adr/0001-joern-fallback.md))
- **Review mode.** Optional human-gated pipeline: each stage pauses at a review gate; approve to
  advance or retry a stage. ([ADR-0005](docs/adr/0005-review-mode-editorial-pipeline.md))
- **Developer Lab API** (`GET /api/dev/options`, `POST /api/dev/llm-settings`): switch LLM model,
  set a per-runtime API key, toggle LLM bypass; sample-repo selector (`sample://buffer-overflow`).
- **Admin dashboard API** (`/admin/dashboard*`) backed by PostgreSQL persistence: aggregate stats,
  paginated/filterable job list, per-user stats.
- **Report endpoint & viewer** (`GET /api/jobs/{id}/report`): source→sink taint graph, main→vuln
  call-path graph, and an original-vs-patch Monaco diff.
- **Template-based per-job fuzzing environment**: `Dockerfile.template` with LLM-injected
  `{{ TARGET_DEPS }}` built per job over a mounted Docker socket.
  ([ADR-0002](docs/adr/0002-docker-in-docker-per-job-env.md))
- **LLM self-feedback loops** for harness compilation and Docker builds (≤3 retries).
  ([ADR-0003](docs/adr/0003-llm-feedback-loops.md))
- **Patch grounding**: AI patches are generated against the isolated real vulnerable function and
  spliced back, not free-form.
- **`DEBUG_BYPASS_LLM`** local mode (fixtures in `backend/debug_assets/`) and a
  **`DEBUG_TEST_TCPDUMP`** end-to-end resilience mode.

### Changed
- Frontend dashboard rebuilt; report viewer and admin dashboard UIs aligned.
- SAST output streamed line-by-line to the dashboard with a heartbeat; `error_hint` surfaced on
  failures.
- CodeQL invocation moved to `--build-mode=none` in the backend; resource caps via
  `CODEQL_THREADS` / `CODEQL_RAM_MB`.

### Fixed
- **WebSocket relay busy-loop** that wedged the FastAPI event loop and froze the live dashboard
  while jobs kept running. ([ADR-0004](docs/adr/0004-redis-pubsub-ws-relay.md))
- Harnesses missing `__AFL_FUZZ_INIT()` are now repaired deterministically before compilation.
- Fuzzer-container `core_pattern` and crash-detection path issues; harness file handoff.

---

_For the full commit-level history, see `git log`._
