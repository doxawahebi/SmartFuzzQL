# ADR-0001: Build-free Joern fallback when CodeQL can't build or finds nothing

- **Status:** Accepted
- **Date:** 2025-06-03

## Context

CodeQL only finds bugs when it can build a usable database. In the CLI runtime CodeQL compiles
the target (`codeql database create … --command="make"`), so a target that won't build aborts
the whole run. The Compose runtime uses `--build-mode=none`, which never compiles but frequently
extracts *nothing* for non-trivial real-world C/C++ (missing headers, custom build systems).
Either way CodeQL can come up empty, and when it does the entire pipeline (harness → fuzz →
patch) has no vulnerability to act on and the job dies at stage 1. For an "any GitHub repo"
tool, that is the common case, not the edge case.

## Decision

Wire **Joern** in as a build-free SAST fallback. Joern's `c2cpg` extracts an AST/CFG/CPG
directly from source with a fuzzy parser — no compilation, no headers, no build system. In
`_run_sast_stage` (`tasks.py`) and `step_2_static_analysis` (`pipeline.py`): run CodeQL first;
if it **raises** or **returns zero findings** and `JOERN_FALLBACK` is enabled (default), run
Joern. `JOERN_FORCE=True` skips CodeQL entirely (for testing the Joern path).

Crucially, Joern's output is converted to the **exact SARIF shape CodeQL emits**
(`joern_raw_to_sarif()` in `joern_analysis.py`) and written to the same `sarif_path` /
`callgraph_sarif_path`. Every downstream consumer is unchanged and cannot tell which engine
produced the SARIF. The dangerous-sink and input-source lists are defined once
(`DANGEROUS_FUNCS` / `INPUT_SOURCE_FUNCS`) and passed to both the queries and the Joern script
so they never drift.

## Consequences

- **Easier:** the pipeline no longer aborts at SAST on a build failure — it degrades to Joern,
  so far more repos reach the fuzzing and patching stages.
- **Harder / accepted:** Joern's fuzzy parsing is less precise than a real CodeQL build, so the
  fallback can produce lower-fidelity findings. The `bootp_print` structural query is *not*
  ported to Joern.
- **Invariant to preserve:** the SARIF adapter is the contract. If you change a query's rule id,
  sink list, or result shape, update the Joern adapter and the shared constants in lock-step
  (covered by `backend/test_joern.py`).

See [sast-analysis.md](../sast-analysis.md) for the full mechanism.
