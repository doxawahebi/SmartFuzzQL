# ADR-0003: Feed compiler/Docker stderr back to the LLM (≤3 retries)

- **Status:** Accepted
- **Date:** 2025-05

## Context

Two LLM-generated artifacts routinely fail on the first try: the AFL++ **harness** (won't
compile against the real target) and the per-job **Dockerfile deps** (apt package guess is
wrong, build fails). A single-shot "generate and hope" approach wastes the whole expensive
pipeline run whenever the LLM's first guess is slightly off — which is often, because the model
is guessing about a codebase it only partially sees.

## Decision

Wrap the fragile LLM steps in **bounded feedback loops**. When generation produces something
that fails, feed the concrete failure back to the LLM and let it self-correct, up to **3
retries**:

- **Harness compile failure** → the compiler stderr is appended to the prompt and the harness is
  regenerated.
- **Dockerfile build failure** → the `docker build` stderr is fed back and the dependency list is
  regenerated.
- **Fuzzing timeout** → AFL++ stats are fed back so the LLM can adjust the harness.

## Consequences

- **Easier:** dramatically higher first-job success rate without human intervention; the system
  recovers from the LLM's typical near-misses.
- **Harder / accepted:** each retry costs another LLM call and another compile/build cycle, so a
  pathological target can spend several minutes looping before giving up. The retry cap (3) bounds
  this but also means genuinely hard targets still fail — by design, rather than hanging.
- **Known flakiness:** the harness occasionally omits the `__AFL_FUZZ_INIT()` macro required by
  AFL++ persistent mode; `_ensure_afl_fuzz_init()` injects it defensively. See
  [dynamic-analysis.md](../dynamic-analysis.md) and the troubleshooting entry in
  [operations.md](../operations.md#troubleshooting--error-catalog).
