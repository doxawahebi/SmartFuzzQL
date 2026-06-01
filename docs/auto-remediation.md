# Auto-Remediation Specification

This document is the as-built specification for the **Auto-Remediation** feature of
SmartFuzzQL (HAST). It describes the current behaviour exactly as implemented so the
feature can be maintained and re-implemented faithfully.

> Terminology: a single pipeline run is always a **job** in API responses, logs, and UI —
> never "task" (Celery's internal term) or "scan".

## 1. Overview

Auto-Remediation is **Stage 4 (`AI_PATCH`)** of the analysis pipeline. Once the DAST stage
has proven a crash, the LLM (Gemini) is asked to generate a secure patch for the vulnerable
C source. The patch is persisted in PostgreSQL, served via the report API, and rendered on
the React dashboard as a side-by-side Monaco diff against the original code.

```
SAST  →  AI_HARNESS  →  DAST (crash proven)  →  AI_PATCH  →  DB_STORAGE  →  PIPELINE/Success
                                                  ▲                              │
                                          this document                  carries patch_code
```

The remediation logic shared by the backend and the CLI lives in `backend/patching.py`
(single source of truth for the prompt and the function-scoped diff). Implementation:
`backend/tasks.py` (`_run_pipeline_impl`), `pipeline.py` (`step_5_patch`, CLI parity),
`backend/main.py` (report API), `frontend/src/ReportViewer.jsx` +
`frontend/src/Dashboard.jsx` (UI).

## 2. Inputs

The patch step receives three inputs gathered by earlier stages:

| Input | Source | Notes |
|-------|--------|-------|
| Vulnerable function | the C function enclosing the SAST sink line, extracted from `vuln_file` | `patching.extract_vulnerable_function(vuln_code, vuln_line)`; falls back to a truncated file (≤ 3000 chars) only when the function can't be isolated |
| Vulnerability message | CodeQL SAST finding (`vuln_msg`) | human-readable description of the taint-flow bug |
| Crash input | AFL++ crash bytes (`crash_data`) | hex-encoded with `crash_data.hex()`; `"Unknown"` if no crash bytes |

The sink line comes from the SARIF finding's `physicalLocation.region.startLine`. Feeding the
LLM the **enclosing function** (rather than a blind file-head truncation that, for large
targets like tcpdump's `print-bootp.c`, never reaches the sink) is what makes the patch
grounded in the real vulnerable code.

## 3. Patch generation

`backend/tasks.py` AI_PATCH stage, using `backend/patching.py`.

1. Emit progress: `notify_status(task_id, "AI_PATCH", "Running", "Crash verified. Querying LLM for source-code secure patch")`.
2. Isolate the vulnerable function with `patching.extract_vulnerable_function()` (a brace
   matcher; see `find_enclosing_function`).
3. Build the prompt with `patching.build_patch_prompt(snippet, vuln_msg, crash_hex)`, which
   asks for a **drop-in replacement of the same function** (same signature, minimal change):

   ```
   You are fixing a security vulnerability in C code.
   Crash input (hex): {crash_hex}
   Vulnerability: {vuln_msg}
   Patch ONLY the function below. Keep the same function signature so it is a drop-in
   replacement, change as little as possible, and do not add commentary.
   Vulnerable function:
   ```c
   {enclosing function}
   ```
   Return ONLY the complete patched function inside a single ```c code block.
   ```

4. Call the model: `call_llm_api(patch_prompt, model="gemini-2.5-flash", task_type="patch")`.
   `task_type="patch"` enables debug-mode dispatch (see §8).
5. Extract the patched function with `extract_c_code()` (```c fence → generic fence → raw).
6. **Splice** the patched function back into the full original file with
   `patching.splice_patch(vuln_code, vuln_line, patched_function)` → this becomes `patch_code`.
   When the enclosing function can't be isolated, the LLM is given the truncated file and its
   raw response is used as-is (legacy fallback).
7. Write the result to disk at `{repo_path}/patched_{basename(vuln_file)}`.

The model is `gemini-2.5-flash` for the web backend (`gemini-2.5-pro` for the CLI). All LLM
calls go through `call_llm_api` — do not introduce another SDK.

## 4. Persistence

On the `DB_STORAGE` stage (`backend/tasks.py:701–752`) the `Job` row keyed by `task_id`
is updated. Relevant columns (`backend/models.py`):

| Column | Type | Meaning |
|--------|------|---------|
| `original_code` | Text | full vulnerable source (the diff's left side) |
| `patch_code` | Text | full source with the vulnerable function replaced by the patched one (the diff's right side) |
| `patch_generated` | Boolean | set `True` once a patch is produced |
| `crash_hex` | Text | hex-encoded crash bytes (or `None`) |
| `code_snippet` | Text | first 500 chars of the source (preview / fallback) |
| `taint_path`, `call_path` | JSON | source→sink and main→vuln graphs (rendered alongside the diff) |

`original_code` is the source read during the run; if the file could not be read it is
stored as `None` and `code_snippet` is also `None`.

## 5. Report API contract

`GET /api/jobs/{task_id}/report` (`backend/main.py:520–583`). See `docs/api-spec.md` for the
full endpoint reference. The Auto-Remediation payload is the `diff` object:

```json
{
  "diff": {
    "original": "void f(char* s) { char buf[10]; strcpy(buf, s); }",
    "patched":  "void f(char* s) { char buf[10]; strncpy(buf, s, 9); buf[9] = 0; }",
    "language": "c"
  }
}
```

Field construction (`backend/main.py`, schemas at `main.py:167–191`):

- `diff.original` = `job.original_code or job.code_snippet or ""` (the full file)
- `diff.patched` = `job.patch_code or ""` (the full file with only the vulnerable function
  replaced). Because both sides are the same file and only the function region differs, the
  Monaco diff is minimal and aligned, and the SARIF/graph line numbers on the original side
  still resolve so the ReportViewer node-click line reveal keeps working.
- `diff.language` is inferred from the `vuln_file` extension:

  | Extension | `language` |
  |-----------|-----------|
  | `.c`, `.h` | `c` |
  | `.cpp`, `.cc`, `.cxx`, `.hpp` | `cpp` |
  | anything else | `plaintext` |

Status codes:

- `200` — job is `SUCCESS`; full report (including `diff`) returned.
- `404` — no job with that `task_id`.
- `409` — job exists but is not yet `SUCCESS`; the current state is returned in the
  `X-Job-State` response header.

## 6. WebSocket lifecycle

See `docs/websocket.md` for the full event schema. For Auto-Remediation:

- The `AI_PATCH` step emits `Running`, then `Success` (or `Failed`).
- The terminal `PIPELINE / Success` event carries a `result` object with the patch summary
  consumed by the dashboard (`backend/tasks.py:771–786`):

  ```json
  {
    "step": "PIPELINE",
    "status": "Success",
    "result": {
      "patch_generated": true,
      "patch_code": "…patched C source…",
      "crash_hex": "deadbeef"
    }
  }
  ```

## 7. Frontend rendering

**ReportViewer** (`frontend/src/ReportViewer.jsx`, route `/report/:id`):

- Fetches `GET /api/jobs/{id}/report` and renders the right-hand panel as a
  `@monaco-editor/react` `<DiffEditor>`:
  - `original={report.diff.original}`, `modified={report.diff.patched}`,
    `language={report.diff.language}`.
  - options: `renderSideBySide: true`, `readOnly: true`, `theme: "vs-dark"`,
    `minimap.enabled: false`, `lineNumbers: "on"`.
- Clicking a node in the taint-flow / call-path graph (left panel) reveals and amber-highlights
  the corresponding line in the original editor.
- Load errors surface a "Failed to load report" message with a link back to the dashboard
  (covers the `404` / `409` API responses).

**Dashboard** (`frontend/src/Dashboard.jsx`, route `/dashboard`):

- Shows a `PATCH GENERATED` / `NO PATCH` badge driven by `pipelineResult.patch_generated`.
- Renders `pipelineResult.patch_code` in a read-only Monaco editor.
- Provides a `View Full Report →` link to `/report/{taskId}`.

## 8. Debug / mock mode

Two independent bypass modes exist:

- **`DEBUG_BYPASS_LLM`** (generic): `call_llm_api` short-circuits the Gemini call and, for
  `task_type="patch"`, returns `backend/debug_assets/mock_patch.c` — a generic `strcpy` →
  bounded `strncpy` patch for the generic test target.
- **`DEBUG_TEST_TCPDUMP`** (tcpdump end-to-end, `backend/debug_tcpdump.py`): every real stage
  runs first; only on LLM failure does the patch fall back. The fallback **synthesizes a
  topical patch from the real `bootp_print` function embedded in the prompt** (inserting the
  missing `ND_TCHECK` bound check), falling back to `backend/debug_assets/bootp_patch.c` when
  no usable function is present. This replaced the earlier behaviour where the unrelated
  generic `mock_patch.c` was shown for a tcpdump run.

## 9. Acceptance criteria

A correct implementation must satisfy (cf. `backend/test_report.py`,
`backend/test_debug_tcpdump.py`):

- After a successful job, `GET /api/jobs/{id}/report` returns `200` with both
  `diff.original` and `diff.patched` non-empty and matching the stored original/patched code.
- `diff.language` is `"c"` for a `.c` vulnerable file (and `cpp` / `plaintext` per the table in §5).
- Before the job reaches `SUCCESS`, the report endpoint returns `409` with an `X-Job-State` header.
- A missing job returns `404`.
- The `AI_PATCH` step publishes `Running` then `Success`, and the terminal `PIPELINE/Success`
  event carries `patch_generated`, `patch_code`, and `crash_hex`.
- With `DEBUG_BYPASS_LLM` enabled the patch is sourced from `mock_patch.c` and is non-empty.
