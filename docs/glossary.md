# Glossary

Domain terms used across the codebase and docs. When in doubt about wire shapes, defer to
[api-spec.md](api-spec.md), [websocket.md](websocket.md), and [database-schema.md](database-schema.md).

| Term | Meaning |
|------|---------|
| **SmartFuzzQL / HAST** | The platform. Name = AI + Fuzzer + CodeQL. Chains SAST → harness → fuzz → patch → report. |
| **Job** | One end-to-end pipeline run for one target. The canonical noun — used in the API, UI, and DB. Never call it a "task" (Celery's term) or a "scan". |
| **Pipeline** | The fixed sequence of stages a job goes through: INIT → SAST → AI_HARNESS → ENV_GEN → DAST → AI_PATCH → DB_STORAGE → PIPELINE. |
| **Stage / step** | One unit of the pipeline. `step` is the field name carried on every `/ws` event. |
| **SAST** | Static Application Security Testing — analysing source without running it. Here: CodeQL (primary) or Joern (fallback). |
| **DAST** | Dynamic Application Security Testing — finding bugs by executing the program. Here: AFL++ fuzzing of the compiled harness. |
| **CodeQL** | GitHub's static-analysis engine. Builds a database of the code and runs `.ql` queries over it. |
| **SARIF** | Static Analysis Results Interchange Format — the JSON CodeQL emits. Joern findings are adapted into the same shape. |
| **Joern** | A build-free static-analysis tool whose `c2cpg` parser extracts an AST/CFG/CPG from source without compiling. Used as the CodeQL fallback. |
| **CPG** | Code Property Graph — the combined AST/CFG/data-flow graph Joern produces. |
| **Taint flow** | A path by which untrusted input (a **source**) reaches a dangerous operation (a **sink**) through **intermediate** steps. Rendered as the report's taint graph. |
| **Source / sink** | Source = where untrusted data enters (e.g. `argv`, `getenv`, `recv`). Sink = a dangerous call (e.g. `strcpy`, `sprintf`). The dangerous set is `DANGEROUS_FUNCS`. |
| **Call path** | The reachability chain from `main` to the vulnerable function. The report's second graph. |
| **Harness** | A small C program the LLM writes so AFL++ can feed fuzzed bytes into the vulnerable function. |
| **AFL++** | The fuzzer. Mutates inputs to drive the instrumented harness toward a crash. |
| **`__AFL_FUZZ_INIT()`** | A macro AFL++ persistent-mode harnesses must declare; injected defensively if the LLM omits it. |
| **Persistent mode** | An AFL++ mode that runs many fuzz iterations per process for speed; requires the init macro and a specific loop shape. |
| **Crash** | A target failure (e.g. segfault) AFL++ found, proving the bug. Stored as `crash_hex` (hex-encoded input). |
| **ENV_GEN** | The stage that builds a per-job fuzzing Docker image, injecting LLM-suggested apt deps into `Dockerfile.template`. |
| **Patch** | The LLM-generated secure replacement for the vulnerable function, spliced back into the source. Shown as a diff. |
| **Review mode** | Optional human-gated pipeline: each stage pauses at a **review gate** for approve/retry before advancing. |
| **Review gate** | The pause point in review mode; the job sits at `review_state: "waiting"` until the user acts. |
| **`sample://`** | A pseudo-URL for a bundled local target (e.g. `sample://buffer-overflow`) — no network needed. |
| **`inline://`** | The internal repo-URL prefix assigned when a job is submitted as raw `source_code` instead of a repo. |
| **`notify_status`** | The worker helper that publishes every progress event to the Redis `pipeline_logs` channel. |
| **`PipelineContext` / `*StageResult`** | The per-job context object and the typed dataclass each stage returns (`SastStageResult`, `HarnessStageResult`, `DastStageResult`, `PatchStageResult`). |
| **`error_hint` / `failure_detail`** | The actionable hint attached to a recoverable failure (`PipelineUserError.hint`), surfaced on `/ws` and stored on the job. |
| **Developer Lab** | The dev-only UI/API (`/api/dev/*`) for switching LLM model, setting a runtime key, and toggling bypass. |
