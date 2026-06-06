# ADR-0005: Optional human-gated "review mode" pipeline

- **Status:** Accepted
- **Date:** 2025-06

## Context

The classic pipeline runs all stages back to back and hands the user a finished report. That is
ideal for automation, but it gives a security analyst no chance to inspect or correct an
intermediate artifact — e.g. to reject a wrong SAST finding before the system spends minutes
fuzzing it, or to retry a bad harness — without re-running the entire job from scratch.

## Decision

Add an opt-in **review mode** (`review_mode: true` on `POST /api/jobs`). Instead of one
`run_pipeline` task, each stage runs as its own Celery task (`run_review_sast_stage`,
`run_review_harness_stage`, …) and then **pauses** at a review gate, setting
`review_state: "waiting"`. The user advances with `POST /api/jobs/{id}/review/approve` or redoes
the current stage with `…/review/retry`. Stage order is `REVIEW_STAGE_ORDER` and the
downstream-invalidation rules (retrying SAST clears harness/DAST/patch results) are
`REVIEW_DOWNSTREAM`, both in `tasks.py`. State is carried in the `jobs` columns `current_stage`,
`review_state`, `stage_results`, and `stage_artifacts`.

## Consequences

- **Easier:** analysts get a human-in-the-loop checkpoint at every stage and can retry one stage
  without losing the rest; the same job row replays cleanly.
- **Harder / accepted:** two execution paths now exist (one-shot `run_pipeline` vs. the
  per-stage review tasks) and must be kept behaviorally consistent; review mode adds extra
  columns and state transitions to reason about. The downstream-invalidation table must stay
  correct or a retry can leave stale results from a later stage.
- **Invariant to preserve:** every review-state transition goes through the same `notify_status`
  events so the dashboard and DB stay in sync. See `backend/test_review_mode.py` and
  [database-schema.md](../database-schema.md) for the state machine.
