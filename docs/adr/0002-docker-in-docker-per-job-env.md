# ADR-0002: Per-job fuzzing image via mounted Docker socket

- **Status:** Accepted
- **Date:** 2025-05

## Context

Fuzzing arbitrary C/C++ targets with AFL++ requires building the target with the AFL++
instrumenting compilers, which in turn requires the target's own system dependencies (apt
packages, headers). Those dependencies differ for every repo and are not known until analysis
time. Running the fuzzer in the worker process itself would (a) pollute the worker with
arbitrary target build deps, (b) give untrusted target code the worker's privileges, and (c)
make crashes hard to isolate.

## Decision

Build and run a **fresh fuzzing container per job**. The Celery `worker` mounts the host Docker
socket (`/var/run/docker.sock:/var/run/docker.sock` in `docker-compose.yml`) so it can drive the
host Docker daemon. `build_dynamic_fuzzing_env` renders `backend/Dockerfile.template`, injecting
LLM-suggested apt packages at the `{{ TARGET_DEPS }}` placeholder — the dependency layer is last,
so the heavy AFL++ base layers stay cached across jobs. The target source is copied into the
image and fuzzed in isolation.

## Consequences

- **Easier:** per-job dependency isolation; untrusted target builds/crashes are contained in a
  throwaway container, not the worker; AFL++ base layers are cached so only the deps layer
  rebuilds.
- **Harder / accepted:** mounting the Docker socket is effectively host-root and is a real trust
  boundary — only run the worker on infrastructure you control (see
  [SECURITY.md](../../SECURITY.md)). The worker depends on a reachable Docker daemon.
- **Invariant to preserve:** **do not alter the structure of `Dockerfile.template`** — the
  `{{ TARGET_DEPS }}` placeholder and layer order are required for the per-job injection and
  caching to work. See [dynamic-analysis.md](../dynamic-analysis.md).
