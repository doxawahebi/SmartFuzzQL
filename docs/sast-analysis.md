# Static Analysis (SAST) Stage

The SAST stage is **stage 1** of the pipeline (the `SAST` step). It runs CodeQL over the
cloned target to (a) find a taint-flow vulnerability and (b) build the supporting graphs the
report viewer renders. It is the counterpart to `docs/auto-remediation.md` (stage 4).

- **Backend entry point:** `run_codeql_analysis()` in `backend/tasks.py`, wrapped by
  `_run_sast_stage()`.
- **CLI entry point:** `step_2_static_analysis()` in `pipeline.py`.
- **Queries:** `backend/queries/` (a single CodeQL pack, `smartfuzzql/cpp-custom`, depending
  on `codeql/cpp-all`).
- **Output:** a `SastStageResult` (vuln message/file/line/code, the raw SARIF `results`, and
  the call-graph results) consumed by every later stage.

---

## Two-Pass Analysis

`run_codeql_analysis()` runs CodeQL in two passes against one database created with
`--build-mode=none` (no compilation of the target is required):

| Pass | Queries dir | Output | Failure behaviour |
|------|-------------|--------|-------------------|
| 1 — vulnerabilities | `backend/queries/vulnerabilities/` | `sarif_path` | Raises — caught by `_run_sast_stage`, which falls back to Joern (see [Hybrid Engine](#hybrid-engine-joern-fallback)) |
| 2 — call graph | `backend/queries/callgraph/` | `callgraph_sarif_path` | **Non-fatal** — emits `SAST / Warning` and continues |

The passes live in separate subdirectories of the same pack so each `codeql database analyze`
invocation runs only its own queries. Between database creation and pass 1, the worker runs
`codeql pack install` best-effort; if that fails (offline worker) it emits a `Warning` and
relies on `--search-path=/opt/codeql/qlpacks`.

**Resource tuning:** both analyze passes use `--threads=$CODEQL_THREADS` (default `1`) and
`--ram=$CODEQL_RAM_MB` (default `2048`). If CodeQL is OOM-killed (exit `137`), the worker
raises a `PipelineUserError` whose `error_hint` ("Lower CODEQL_RAM_MB/CODEQL_THREADS, increase
Docker/WSL memory…") is surfaced to the dashboard over `/ws` (see `docs/websocket.md`).

**Streaming progress:** CodeQL stdout is streamed line-by-line as `SAST / Running` events, with
a 15-second heartbeat when a command is quiet ("…still running… elapsed=Ns, no new CodeQL
output for Ms") so the dashboard never looks stalled during a long database build.

On success the stage emits `SAST / Success` with the `vuln` enrichment field (message, file,
first 500 chars of the vulnerable file). The `details` string names the engine that produced
the finding (`Found vulnerability via CODEQL: …` or `… via JOERN: …`).

---

## Hybrid Engine: Joern Fallback

CodeQL only finds bugs when it can build a usable database. The CLI compiles the target
(`codeql database create … --command="make"`), so a target that won't build aborts the run;
the backend uses `--build-mode=none`, which never compiles but frequently extracts *nothing*
for non-trivial C/C++. Either way CodeQL can come up empty.

**Joern** is wired in as a build-free fallback. It extracts an AST/CFG/CPG directly from source
with its fuzzy C/C++ parser (c2cpg) — **no compilation, no headers, no build system**.

**When Joern runs** (`_run_sast_stage` in `tasks.py`; `step_2_static_analysis` in `pipeline.py`):

1. CodeQL runs first (unless `JOERN_FORCE=True`).
2. If CodeQL **raises** (e.g. the CLI's `make` build fails) **or returns zero vuln findings**,
   and `JOERN_FALLBACK` is enabled (default), Joern takes over.
3. The pipeline never aborts at the SAST stage on a build failure — it degrades to Joern.

**How it stays drop-in compatible.** Joern's findings are converted into the **exact SARIF
shape CodeQL emits** and written to the same `sarif_path` / `callgraph_sarif_path`. Every
downstream consumer (`_select_vulnerability`, `_select_taint_result` / `_extract_taint_path`,
`_parse_call_edges` / `_extract_call_path`, `SastStageResult`, and all later stages) is
unchanged — it cannot tell which engine produced the SARIF.

| Piece | Location | Role |
|-------|----------|------|
| `joern/extract_vulns.sc` | `backend/joern/` | Joern Scala script: imports source, runs taint flows + call edges, writes neutral `joern_raw.json` |
| `joern_raw_to_sarif()` | `backend/joern_analysis.py` | Pure adapter: neutral JSON → `(vuln_sarif, callgraph_sarif)` matching CodeQL; normalizes paths to repo-relative URIs |
| `run_joern_analysis()` | `backend/joern_analysis.py` | Runs Joern, calls the adapter, writes both SARIF files (shared by backend + CLI) |

The Joern script mirrors the CodeQL queries it replaces: the same dangerous sinks and untrusted
input sources (defined once in `joern_analysis.DANGEROUS_FUNCS` / `INPUT_SOURCE_FUNCS` and
passed to the script as `--param`, so `tasks.py`, the queries, and Joern never drift) and the
same `cpp/taint-buffer-overflow` / `cpp/call-graph-edges` rule ids. The `bootp_print` structural
query is **not** ported to Joern.

**Environment toggles:**

| Variable | Default | Effect |
|----------|---------|--------|
| `JOERN_FALLBACK` | `True` | Enable the Joern fallback. Set `False` to keep CodeQL-only behaviour. |
| `JOERN_FORCE` | `False` | Skip CodeQL and run Joern directly (for testing the Joern path). |

Joern (CLI + JVM) is installed into both images at `/opt/joern/joern-cli` (see
`backend/Dockerfile` and the root `Dockerfile`); it needs JDK ≥ 17. The unit tests in
`backend/test_joern.py` prove the adapter's SARIF is consumable by the real downstream parsers
without needing Joern or Docker installed.

---

## Query Packs

### `vulnerabilities/taint_buffer_overflow.ql` — the primary finding

- `@kind path-problem`, `@id cpp/taint-buffer-overflow`, CWE-120 / CWE-787, security-severity 8.0.
- **Sources:** any function parameter, plus the result of common untrusted-input calls
  (`getenv`, `fgets`, `read`, `recv`, `fread`).
- **Sinks:** the last argument of a call to a dangerous C string function — `strcpy`, `strcat`,
  `gets`, `sprintf`, `vsprintf`, `scanf` (the `DangerousFunction` class).
- Because it is a `path-problem`, each result carries SARIF `codeFlows`. These become the
  **taint_path** graph in the report (`_extract_taint_path()` in `tasks.py`): the first node
  is `source`, the last is `sink`, the rest are `intermediate`.

### `vulnerabilities/bootp_print.ql` — structural finding (tcpdump)

- `@kind problem`, `@id cpp/bootp-missing-ndtcheck`, security + correctness.
- Flags `EXTRACT_*BITS` reads inside `bootp_print` that lack a preceding `ND_TCHECK*` bounds
  check on the same struct field (heap out-of-bounds read via a crafted BOOTP/DHCP packet).
- Has no `codeFlows`, so it produces no taint_path; it is the finding used by the
  `DEBUG_TEST_TCPDUMP` end-to-end path.

### `callgraph/call_graph.ql` — reachability (supplementary)

- `@kind problem`, `@id cpp/call-graph-edges`, severity `recommendation`. **Not a security
  finding** — it exists only to feed the call-path graph.
- Emits every static call edge from a repo-defined caller to another repo-defined function (or
  to a dangerous sink), encoding it in the result message as
  `CALL_EDGE <caller> -> <callee>`. The result location is the call site.
- The dangerous-sink list is intentionally kept in sync with `taint_buffer_overflow.ql` and the
  `DANGEROUS_FUNCS` set in `tasks.py`.

---

## From SARIF to the Report

After the two passes, `_run_sast_stage()` selects the finding and builds the graphs:

1. **Pick the vulnerability** — `_select_vulnerability()` / `_select_taint_result()` prefer a
   result that has `codeFlows`; the message, file (repo-relative `uri`), and start line are
   extracted.
2. **Read the source** — `_read_vulnerable_code()` loads the full file, or returns the
   `CODE_NOT_FOUND` sentinel; `_code_snippet_or_none()` yields the 500-char snippet (or `None`).
3. **taint_path** — `_extract_taint_path()` turns the SARIF `codeFlows` into `{nodes, edges}`.
4. **call_path** — `_parse_call_edges()` parses the `CALL_EDGE` messages, then
   `_extract_call_path()` runs a BFS from `main` to the vulnerable function to produce the
   shortest reachability chain (roles map `source`=`main`, `intermediate`=caller,
   `sink`=vulnerable fn). Empty `{nodes: [], edges: []}` when the call-graph pass was skipped.

Both graphs are persisted to the `taint_path` / `call_path` JSONB columns in `DB_STORAGE` and
served by `GET /api/jobs/{task_id}/report` (`docs/api-spec.md`). The ReportViewer renders them
in its **Taint Flow** and **Call Path** tabs.

---

## Constants

| Name | Location | Meaning |
|------|----------|---------|
| `DANGEROUS_FUNCS` | `tasks.py` | `{strcpy, strcat, gets, sprintf, vsprintf, scanf}` — kept in sync with the queries |
| `CALL_EDGE_RULE_ID` | `tasks.py` | `cpp/call-graph-edges` — filter for call-graph SARIF results |
| `CODE_NOT_FOUND` | `tasks.py` | Sentinel returned when the vulnerable source file can't be read |

---

## Adding a New Query

1. Drop the `.ql` into `backend/queries/vulnerabilities/` (findings) or
   `backend/queries/callgraph/` (reachability) — it is picked up automatically by the matching
   pass; no registration needed.
2. For a taint finding, use `@kind path-problem` so `codeFlows` (and therefore the taint_path
   graph) are produced.
3. If you add a dangerous sink, update **all three** of `taint_buffer_overflow.ql`,
   `call_graph.ql`, and `DANGEROUS_FUNCS` in `tasks.py` so the taint query, the call graph, and
   the Python helpers stay consistent.
