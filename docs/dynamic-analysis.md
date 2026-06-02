# Dynamic Analysis (Harness + DAST) Stage

This covers **stages 2–3** of the pipeline — `AI_HARNESS` (generate an AFL++ fuzzing harness)
and `DAST` (build the fuzzing image, compile the harness, and fuzz until a crash). The
per-job Docker image build is reported under the auxiliary `ENV_GEN` step. Together they turn
the SAST finding into a *proven* crash (the hex-encoded input passed to stage 4, see
`docs/auto-remediation.md`).

- **Backend:** `_run_ai_harness_stage()` → `_run_dast_stage()` → `run_dast_fuzzing()` in
  `backend/tasks.py`; the image is built by the `build_dynamic_fuzzing_env` Celery task.
- **CLI:** `step_3_4_dynamic_harness_loop()` in `pipeline.py`.

---

## AI_HARNESS — harness generation

`_run_ai_harness_stage()` asks Gemini (`gemini-2.5-flash`, `task_type="harness"`) for a
**complete AFL++ persistent-mode** C harness targeting the vulnerable file. The prompt requires:

- `__AFL_FUZZ_INIT();` at global scope (after the `#include`s, before `main`),
- a `while (__AFL_LOOP(1000))` loop reading the test case from
  `__AFL_FUZZ_TESTCASE_BUF` / `__AFL_FUZZ_TESTCASE_LEN`,
- a developer-defined `int main()` (**not** `LLVMFuzzerTestOneInput`),
- a call into the vulnerable function so the crash is reachable.

The LLM output is run through `extract_c_code()` (strips the ```` ```c ```` fence) and then
`_ensure_afl_fuzz_init()`. The latter **deterministically inserts `__AFL_FUZZ_INIT();`** at
global scope when the harness uses the persistent-mode macros but omits the init — a frequent
`gemini-2.5-flash` mistake that otherwise fails to compile with
`use of undeclared identifier '__afl_fuzz_ptr'`. The harness is written to
`{repo_path}/harness.c`. This stage emits only `AI_HARNESS / Running`.

---

## ENV_GEN — per-job fuzzing image

`run_dast_fuzzing()` first calls `_start_fuzzing_container()`, which invokes the
`build_dynamic_fuzzing_env` Celery task. This builds a fresh image **per job** from
`backend/Dockerfile.template`:

1. **Build context** — clone the repo with `git clone --depth 1` (or `copy_sample_repo()` for a
   `sample://` URL) into a temp dir.
2. **Dependency resolution** — read up to 3 000 chars each of `README.md`, `configure`,
   `configure.ac`, `CMakeLists.txt`, `Makefile`, `autogen.sh`, and ask Gemini
   (`task_type="docker_deps"`) for a space-separated list of Ubuntu `apt` packages. For a
   `sample://` repo the LLM is skipped and the deps are hardcoded to `pkg-config`.
3. **Injection** — substitute the deps into the `{{ TARGET_DEPS }}` placeholder of
   `Dockerfile.template` (Layer 4), write `dynamic-fuzzer.Dockerfile` at the repo root, and
   `docker build -t dynamic-fuzzer-{task_id}`.
4. **Feedback loop** — up to **3 attempts**; on a failed `docker build`, the last 2 000 chars
   of stderr are appended to the prompt and the LLM is asked to fix/add dependencies.

Returns `{"status": "Success", "image": "dynamic-fuzzer-{task_id}"}` or
`{"status": "Failed", "error": ...}`. All `ENV_GEN` progress (`Running` / `Success` / `Failed`)
is emitted over `/ws`.

> **Guardrail:** do not change the structure of `Dockerfile.template`. Layers 1–3 (Ubuntu base,
> OS deps, AFL++ v4.21c build) are cached; the `{{ TARGET_DEPS }}` placeholder in Layer 4 is
> required for per-job dependency injection.

---

## DAST — compile and fuzz

With the image built, `run_dast_fuzzing()` runs the container `privileged` with
`tail -f /dev/null`, then:

### 1. Compile with feedback (`_compile_harness_with_feedback`)

The harness is copied in and compiled with
`afl-clang-fast -fsanitize=address -I/usr/local/include/afl++ -o fuzz_target harness.c`,
for up to **3 attempts**. On failure (before the last attempt) the compiler stdout/stderr,
the original vulnerable source (for correct signatures), and the broken harness are fed back to
Gemini for a fix; the corrected code is re-run through `_ensure_afl_fuzz_init()`. Emits
`DAST / Running` per attempt, `DAST / Warning` on each failed attempt, and `DAST / Success`
("Harness compiled successfully") once it compiles. Exhausting the retries raises.

### 2. Fuzz and poll for a crash (`_run_afl_and_wait_for_crash`)

Seeds `inputs/seed` with `A`, sets `core_pattern`, and launches
`afl-fuzz -i ./inputs -o ./outputs -m none -- ./fuzz_target` in the background (with
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1`). It then polls every
**10 seconds**:

- reads `outputs/default/fuzzer_stats`, parses it with `_parse_afl_stats()`
  (`run_time` → `time_sec`, `execs_done` → `execs`, `unique_crashes` → `crashes`), and emits
  `DAST / Running` with the `fuzz_stats` enrichment field;
- checks `outputs/default/crashes/id:*` — on the first crash, reads the crash file bytes, emits
  `DAST / Success` ("Crash found!"), and returns the bytes.

If no crash appears within the timeout it emits `DAST / Failed` and raises. The crash bytes are
hex-encoded by the patch stage (`crash_data.hex()`) and become `crash_hex` in the report.

> **Timeout note:** the **web backend** polls for **60 s** (`TIME_MINITUTE = 1`) even though the
> kickoff message says "max 20 mins" — short, to keep dashboard demos responsive. The
> **standalone CLI** (`pipeline.py`) uses `FUZZ_TIMEOUT_SEC = 20 * 60` and retries the whole
> harness/fuzz loop up to `MAX_RETRIES = 3` (with `gemini-2.5-pro`). The container is always
> torn down in a `finally` (`_cleanup_container`).

---

## Sample-Repository Protocol

A `repo_url` of the form `sample://<name>` resolves to a bundled local project instead of a git
clone. The registry is `SAMPLE_REPOS` in `tasks.py`:

| URL | Name | Path |
|-----|------|------|
| `sample://buffer-overflow` | Buffer Overflow Sample | `backend/debug_samples/buffer_overflow_repo` |

`is_sample_repo_url()` gates the behaviour; `copy_sample_repo()` copies the tree into the
build/clone dir. Sample repos additionally **skip LLM dependency inference** in `ENV_GEN`
(deps hardcoded to `pkg-config`). They are offered in the Developer Lab via
`GET /api/dev/options` (`docs/api-spec.md`) and can be typed directly into the Dashboard's
repo field.

**To add a sample:** add an entry to `SAMPLE_REPOS` (`url`, `name`, `description`, `path`) and
drop the project under `backend/debug_samples/`. No frontend change is needed — it appears in
the Dev Lab picker automatically.

---

## Related

- `docs/sast-analysis.md` — the SAST finding that drives harness generation.
- `docs/auto-remediation.md` — stage 4, which consumes the crash this stage produces.
- The `__AFL_FUZZ_INIT()` injection guards a known harness-flakiness class; see the
  `_ensure_afl_fuzz_init()` docstring in `tasks.py`.
