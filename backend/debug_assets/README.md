# Debug Assets

This directory contains mock files used by the pipeline when the `DEBUG_BYPASS_LLM` environment variable is strictly enabled (`True`, `1`, or `Yes`).

```dockerfile
worker:
    ...
    environment:
      ...
      - DEBUG_BYPASS_LLM=True
```

When enabled, the backend skips the actual LLM API calls and reads the following files instead:
- `mock_harness.c` - Used instead of waiting for the LLM to write a fuzzing harness.
- `mock_patch.c` - Used instead of waiting for the LLM to write a vulnerability patch.
- `mock_deps.txt` - Used instead of the LLM deciding the system packages for Docker dependencies (optional, defaults to `pkg-config libssl-dev zlib1g-dev` if missing).

Note: If debug mode is on, but the needed mock C file is missing, the backend will log an error and throw an exception to halt the pipeline gracefully.

## `DEBUG_TEST_TCPDUMP` resilience mode

A separate, independent flag (`DEBUG_TEST_TCPDUMP=True`) used to verify the full
tcpdump-4.9.1 flow end-to-end (`https://github.com/doxawahebi/tcpdump-4.9.1`). Unlike
`DEBUG_BYPASS_LLM` (which always mocks the LLM), this mode runs **every real stage** —
`git clone`, CodeQL `bootp_print.ql`, the Docker/AFL++ fuzzing build, and the real LLM
calls — and only falls back **when a stage fails**, so the job always reaches a SUCCESS
`bootp_print` report.

`tasks.py` knows nothing about this mode. The fallback lives entirely in
`backend/debug_tcpdump.py`, which monkeypatches `tasks.py`'s boundary functions
(`clone_repo`, `run_codeql_analysis`, `run_dast_fuzzing`, `call_llm_api`). It is activated
by importing that module — the worker does this via `celery ... --include=debug_tcpdump`,
and the test does it with `import debug_tcpdump`.

On failure it uses the following **real** artifacts (never fabricated stubs):

- `bootp_sa.sarif` — genuine `bootp_print.ql` CodeQL output (copied to the SARIF path when CodeQL fails).
- `harness.c` — genuine bootp_print AFL++ harness. **When the LLM-generated harness fails
  to build 3×, the DAST fallback swaps this in, builds tcpdump (`./configure && make` →
  `libnetdissect.a`), compiles `harness.c -lpcap -lcrypto`, and actually runs AFL++ to find
  a real crash** (retry loop with short in-bounds seeds; `AFL_MAP_SIZE=10000000`; ASan).
  The crash comes from real fuzzing — it is not a canned pcap.
- `mock_patch.c` — patch fallback when the LLM patch call fails.
- `harnss_crash.pcap` / `origin_crash.pcap` — reference crash inputs the user captured
  (not used as the pipeline's crash result; the fuzzer produces its own).

Notes:
- Ubuntu 22.04 ASan can fail to start under the newer (WSL2) host kernel's default ASLR
  entropy; the fallback runs `sysctl -w vm.mmap_rnd_bits=28` (privileged container) to make
  the ASan build + fuzzer reliable.
- `TCPDUMP_FUZZ_TIMEOUT` (per attempt, default 90s) and `TCPDUMP_FUZZ_ATTEMPTS` (default 6)
  tune the fuzzing budget.

Verify live: `DEBUG_TEST_TCPDUMP=True docker compose up --build`, submit
`https://github.com/doxawahebi/tcpdump-4.9.1`, and watch the worker reach
`[DAST] Success - harness.c fuzzing found a real bootp_print crash` → `[DB_STORAGE] Success`
→ `[PIPELINE] Success`, then `GET /api/jobs/{id}/report` returns `state=SUCCESS`.
