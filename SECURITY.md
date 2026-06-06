# Security Policy

This policy is about vulnerabilities **in SmartFuzzQL itself** (the platform). It is not about the
vulnerabilities SmartFuzzQL finds in target code — those are the job reports.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security problem.**

Report privately through one of:

- GitHub's **private vulnerability reporting** ("Report a vulnerability" under the repo's
  *Security* tab), or
- a direct message to the maintainers listed in the repository `README.md`.

Include enough to reproduce: affected component (web API, worker, frontend, CLI), version/commit,
steps, and impact. A minimal proof-of-concept helps; please don't include live third-party
credentials.

### What to expect

- An acknowledgement of your report.
- An assessment and, for confirmed issues, a fix or mitigation.
- Coordinated disclosure — we'll agree on timing before any public write-up, and credit you if
  you'd like.

## Scope & known sharp edges

SmartFuzzQL runs untrusted target code through compilers and a fuzzer, so it is **designed to be
run in a controlled environment**, not exposed to anonymous users. The following are known
operational risks, not bugs:

- **Docker socket mount.** The Celery worker mounts `/var/run/docker.sock` to build and run per-job
  fuzzing containers. That is effectively host-root. Run the worker only on infrastructure you
  control. ([ADR-0002](docs/adr/0002-docker-in-docker-per-job-env.md))
- **Arbitrary target code.** Targets are cloned, compiled, and fuzzed. Isolation is provided by the
  per-job container, not by sandboxing the worker itself.
- **Open CORS / no auth in dev.** The default config allows all origins and does not authenticate
  callers. Add authentication and restrict CORS before any non-local deployment.
- **LLM/secret handling.** `GEMINI_API_KEY` must come from env/`.env`; never commit it. A
  per-runtime key can also be set via the Developer Lab and is stored in Redis (`dev:llm_config`).

Hardening these (auth, CORS, network isolation, secret management) is the operator's
responsibility — see [docs/operations.md](docs/operations.md).
