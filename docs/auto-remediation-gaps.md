# Auto-Remediation — Known Gaps

Companion to [`docs/auto-remediation.md`](auto-remediation.md). That document specifies the
feature **as built**; this one tracks gaps and limitations. Most of the gaps found during the
initial review have since been addressed (see "Resolved"); the remaining one is intentional.

## Remaining (by design)

### Generated patch is not re-validated

The patched function is stored and surfaced without being recompiled or re-fuzzed. Nothing
confirms that the patch (a) compiles or (b) actually eliminates the proven crash, and
`patch_generated` is set `True` whenever a patch is produced.

- **Impact:** `PATCH GENERATED` means "a patch was produced", not "a patch was verified".
- **Status:** Intentionally out of scope — the current feature focuses on giving the LLM the
  real vulnerable code and diffing it against the patch, not on closed-loop verification.
- **Pointer:** `backend/tasks.py` AI_PATCH stage (`patch_generated = True`).

## Resolved

### Standalone CLI has no patch step ✓

`pipeline.py` now has `step_5_patch`, which mirrors the backend AI_PATCH stage via the shared
`backend/patching.py` module, writes `patched_<file>`, and records the diff in the report JSON.

### Patch not grounded in the real vulnerable code / noisy diff ✓

The patch step previously fed the LLM the first ~3000 chars of the file (which, for large
targets like tcpdump's `print-bootp.c`, never contained the sink) and stored a whole-file or
unrelated snippet as the patch. Now `backend/patching.py` extracts the **enclosing function**
around the SARIF sink line, asks for a drop-in replacement, and **splices** it back into the
full file — producing a minimal, aligned diff whose original-side line numbers still match the
SARIF graph.

### tcpdump fallback showed unrelated code ✓

The `DEBUG_TEST_TCPDUMP` patch fallback returned the generic `mock_patch.c`
(`vulnerable_func` / `strcpy`) — unrelated to the actual `bootp_print` over-read. It now
synthesizes a topical patch from the real function in the prompt (inserting the missing
`ND_TCHECK` bound check), falling back to `debug_assets/bootp_patch.c`.

### Prompt drift between CLI and backend ✓

The patch prompt lived only in `tasks.py`. It now lives once in
`backend/patching.build_patch_prompt()` and is used by both `tasks.py` and `pipeline.py`.
