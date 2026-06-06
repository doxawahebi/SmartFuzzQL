# Architecture Decision Records (ADRs)

An ADR captures **one architectural decision** and the reasoning behind it, so the *why*
survives past the people who made it. We use a lightweight format (Context → Decision →
Consequences). When a decision changes, add a new ADR that supersedes the old one rather than
rewriting history.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-joern-fallback.md) | Build-free Joern fallback when CodeQL can't build or finds nothing | Accepted |
| [0002](0002-docker-in-docker-per-job-env.md) | Per-job fuzzing image via mounted Docker socket | Accepted |
| [0003](0003-llm-feedback-loops.md) | Feed compiler/Docker stderr back to the LLM (≤3 retries) | Accepted |
| [0004](0004-redis-pubsub-ws-relay.md) | Decouple worker from FastAPI via Redis PubSub relay | Accepted |
| [0005](0005-review-mode-editorial-pipeline.md) | Optional human-gated "review mode" pipeline | Accepted |

## Writing a new ADR

1. Copy [`template.md`](template.md) to `NNNN-short-title.md` (next number, kebab-case).
2. Fill in Context / Decision / Consequences. Keep it to a page.
3. Add a row to the table above.
4. Link to it from [architecture.md](../architecture.md) where the decision shows up.
