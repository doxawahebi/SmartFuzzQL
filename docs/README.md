# SmartFuzzQL (HAST) — Developer Documentation

This is the entry point for the developer docs. SmartFuzzQL is an automated C/C++ security
analysis platform that chains **CodeQL/Joern SAST → LLM harness generation → AFL++ DAST →
LLM patch generation → reporting** into a single job. If you are new, start with
[Getting Started](getting-started.md).

The docs are organised by *what you are trying to do*, following the
[Diátaxis](https://diataxis.fr/) split (learn / understand / look up / accomplish).

## Onboarding — start here

| Doc | What it gives you |
|-----|-------------------|
| [getting-started.md](getting-started.md) | Prerequisites, install, and a minimal run that reaches a SUCCESS report in a few minutes. |

## Architecture & concepts — the mental model

| Doc | What it gives you |
|-----|-------------------|
| [architecture.md](architecture.md) | System topology, the staged pipeline, data/control flow, core abstractions, classic vs review mode. |
| [adr/](adr/README.md) | Architecture Decision Records — *why* the big tradeoffs were made. |

## Reference — authoritative lookup

| Doc | What it gives you |
|-----|-------------------|
| [api-spec.md](api-spec.md) | Every REST, Developer Lab, and admin endpoint: schemas, params, error codes. |
| [websocket.md](websocket.md) | `/ws` event schema, step lifecycle, server/client integration. |
| [database-schema.md](database-schema.md) | The `jobs` table: columns, states, JSON shapes, how to inspect it. |
| [configuration.md](configuration.md) | Consolidated environment-variable and configuration reference. |
| [sast-analysis.md](sast-analysis.md) | SAST stage internals: CodeQL two-pass, Joern fallback, query packs, graphs. |
| [dynamic-analysis.md](dynamic-analysis.md) | AI_HARNESS + ENV_GEN + DAST internals: harness gen, Docker env, AFL++. |
| [auto-remediation.md](auto-remediation.md) | AI_PATCH stage internals: patch generation, persistence, report rendering. |

## How-to & examples — get a task done

| Doc | What it gives you |
|-----|-------------------|
| [how-to.md](how-to.md) | Recipes: add a query, add an endpoint, add a component, add a pipeline stage, run debug mode. |
| [examples.md](examples.md) | Copy-pasteable curl, WebSocket, and CLI snippets. |

## Operations — run & troubleshoot

| Doc | What it gives you |
|-----|-------------------|
| [operations.md](operations.md) | Deployment, monitoring/observability, troubleshooting, and the error catalog. |

## Contributing & versioning

| Doc | What it gives you |
|-----|-------------------|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Dev setup, tests, code style, branch/PR conventions. |
| [../CHANGELOG.md](../CHANGELOG.md) | Notable changes, plus the contract-stability & deprecation policy. |
| [../SECURITY.md](../SECURITY.md) | How to report a vulnerability in SmartFuzzQL itself. |

## Meta

| Doc | What it gives you |
|-----|-------------------|
| [glossary.md](glossary.md) | Domain terms (SAST, DAST, taint flow, harness, sink, review gate, …). |
| [faq.md](faq.md) | Quick answers to recurring questions, with links to the deep docs. |

---

**Repo-level guidance** also lives in `CLAUDE.md` (root), `backend/CLAUDE.md`, and
`frontend/CLAUDE.md`. Those are concise rule sheets; this `docs/` tree is the long-form
reference they link into.
