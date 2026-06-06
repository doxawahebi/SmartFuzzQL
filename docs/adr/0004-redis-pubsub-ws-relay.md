# ADR-0004: Decouple worker from FastAPI via Redis PubSub relay

- **Status:** Accepted
- **Date:** 2025-06-02

## Context

The dashboard needs **real-time** progress for a running job. The work happens in the Celery
`worker` process; the WebSocket clients are connected to the FastAPI `web` process. These are
separate OS processes (and in Compose, separate containers). The worker has no access to the
FastAPI `ConnectionManager`, so it cannot push to `/ws` directly. We also did not want the
frontend polling the API on a timer.

## Decision

Use Redis PubSub as a one-way relay. The worker's `notify_status()` (`tasks.py`) **publishes** a
JSON event to the `pipeline_logs` channel. The web process runs a single async `redis_listener()`
(`main.py`) that **subscribes** to that channel and fans every message out to all `/ws` clients
via `ConnectionManager.broadcast()`, while also updating the in-memory `job_store` and Postgres.
Worker = publisher only; web = relay only.

## Consequences

- **Easier:** clean process separation; the worker stays ignorant of WebSockets; multiple web
  replicas could each relay; no frontend polling.
- **Harder / accepted:** the relay loop is a critical piece of shared infrastructure — if it
  wedges, every dashboard goes dead while the worker keeps running and the DB keeps updating
  (the failure looks like "the app froze" even though jobs complete). This actually happened: an
  early `redis_listener` busy-loop starved the FastAPI event loop.
- **Invariant to preserve:** `redis_listener()` must never busy-spin. It polls with
  `get_message(timeout=…)` (idle ticks return `None` and keep the *same* subscription alive),
  always closes the PubSub before reconnecting, and backs off on error. Don't reintroduce a tight
  loop. See [websocket.md](../websocket.md) for the full relay contract.
