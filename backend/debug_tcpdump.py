"""DEBUG_TEST_TCPDUMP resilience mode — applied entirely from outside tasks.py.

Verifies the full HAST flow end-to-end against tcpdump-4.9.1
(https://github.com/doxawahebi/tcpdump-4.9.1). It runs every real stage first and, **only
when a stage fails**, substitutes a real artifact / known-good procedure so the job still
reaches a SUCCESS `bootp_print` report:

  - clone : tolerated if offline.
  - SAST  : on CodeQL failure, drop in `debug_assets/bootp_sa.sarif` (genuine
            `bootp_print.ql` output) at the path tasks.py reads.
  - AI    : on LLM failure, use `debug_assets/harness.c` / `mock_patch.c`.
  - DAST  : if the LLM-generated harness fails to build (3 attempts), swap in the
            known-good `debug_assets/harness.c`, build tcpdump (-> libnetdissect.a),
            compile the harness against it, and **actually fuzz with AFL++ to find a real
            crash**. The crash bytes come from real fuzzing — never a canned pcap.

It is independent of `DEBUG_BYPASS_LLM`. `tasks.py` contains no reference to this module:
we monkeypatch the mock-agnostic boundary functions tasks.py exposes (`clone_repo`,
`run_codeql_analysis`, `run_dast_fuzzing`, `call_llm_api`). Activation:

  - runtime worker: `celery -A tasks.celery_app worker --include=debug_tcpdump`
  - tests: `import debug_tcpdump` (auto-activates when the flag is set)
"""
import os
import shutil

import docker

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEBUG_ASSETS = os.path.join(_HERE, "debug_assets")

TCPDUMP_REPO_URL = "https://github.com/doxawahebi/tcpdump-4.9.1"
BOOTP_SARIF = os.path.join(_DEBUG_ASSETS, "bootp_sa.sarif")
HARNESS_C = os.path.join(_DEBUG_ASSETS, "harness.c")
MOCK_PATCH_C = os.path.join(_DEBUG_ASSETS, "mock_patch.c")

# Per-attempt fuzzing budget and number of attempts. bootp_print crashes within seconds
# from short seeds; AFL's forkserver occasionally aborts at startup (ASAN-nondeterministic
# calibration on this harness), so we retry rather than fail.
FUZZ_TIMEOUT = int(os.environ.get("TCPDUMP_FUZZ_TIMEOUT", "90"))     # seconds per attempt
FUZZ_ATTEMPTS = int(os.environ.get("TCPDUMP_FUZZ_ATTEMPTS", "6"))

# Build tcpdump instrumented (-> libnetdissect.a) and link the known-good harness against
# it. The harness has its own main()/__AFL_LOOP, so no -fsanitize=fuzzer.
_BUILD_HARNESS_CMD = (
    # Ubuntu 22.04 ASan + the newer (WSL2) host kernel default ASLR entropy (mmap_rnd_bits=32)
    # intermittently fails to start ASan binaries ("cannot run C compiled programs" /
    # forkserver signal 11). Lowering it to 28 makes the ASan build + fuzzer reliable.
    # Best-effort (the fuzzing container runs privileged); persists for the fuzz step too.
    "sysctl -w vm.mmap_rnd_bits=28 2>/dev/null || true; "
    "cd /target && "
    "CC=afl-clang-fast AFL_USE_ASAN=1 ./configure --disable-shared >/tmp/cfg.log 2>&1 && "
    "CC=afl-clang-fast AFL_USE_ASAN=1 make >/tmp/make.log 2>&1 && "
    "AFL_USE_ASAN=1 afl-clang-fast -DHAVE_CONFIG_H -I. -I/usr/include -g -O1 "
    "harness.c libnetdissect.a -lpcap -lcrypto -o fuzz_target >/tmp/cc.log 2>&1"
)
# Short, in-bounds BOOTP/DHCP request packets (op=1,htype=1,hlen=6). They parse cleanly
# (so AFL's dry run does not crash the forkserver) but are one mutation away from the
# unchecked EXTRACT_16BITS(&bp->bp_flags) read at print-bootp.c -> a quick OOB crash.
_SEED_CMD = (
    "cd /target && rm -rf inputs && mkdir -p inputs && python3 -c \""
    "import os;\n"
    "[open('inputs/s%d'%n,'wb').write(bytes(bytearray([1,1,6]+[0]*(n-3)))) for n in (16,20,22,23,28)]\""
)
# One fuzzing attempt: tcpdump links a huge coverage map -> AFL_MAP_SIZE. Stop on first crash.
_FUZZ_ONE_CMD = (
    "cd /target && rm -rf outputs && mkdir -p outputs && "
    "echo core > /proc/sys/kernel/core_pattern 2>/dev/null; "
    "AFL_MAP_SIZE=10000000 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
    "AFL_BENCH_UNTIL_CRASH=1 ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 "
    "timeout {timeout} afl-fuzz -i inputs -o outputs -m none -- ./fuzz_target "
    ">/tmp/fuzz.log 2>&1; true"
)


def is_enabled() -> bool:
    """True when DEBUG_TEST_TCPDUMP is strictly enabled (True/1/yes)."""
    return os.environ.get("DEBUG_TEST_TCPDUMP", "False").lower() in ("true", "1", "yes")


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# DAST fallback: build the known-good harness and fuzz for a real crash
# --------------------------------------------------------------------------- #
def fuzz_known_good_harness(task_id, repo_url, fuzz_timeout: int = FUZZ_TIMEOUT) -> bytes:
    """Build the AFL++ image, drop in the known-good bootp_print harness.c, build tcpdump
    + the harness, and fuzz until a real crash is produced. Returns the crash input bytes.
    Raises if the build or fuzzing cannot produce a crash.
    """
    import tasks  # boundary helpers (notify_status, build_dynamic_fuzzing_env, copy_text_to_container)

    tasks.notify_status(
        task_id, "DAST", "Running",
        "LLM harness did not build; switching to the known-good bootp_print harness.c and fuzzing for real.",
    )

    build_res = tasks.build_dynamic_fuzzing_env(repo_url, task_id)
    if build_res.get("status") == "Failed":
        raise Exception(f"debug fallback: fuzzing image build failed: {build_res.get('error')}")
    image_name = build_res["image"]

    client = docker.from_env()
    container = client.containers.run(
        image_name, command="tail -f /dev/null", detach=True, working_dir="/target", privileged=True,
    )
    try:
        container.reload()
        if container.status != "running":
            raise Exception("debug fallback: fuzzing container failed to start")

        # Inject the known-good harness (overwrites whatever the LLM produced).
        tasks.copy_text_to_container(container, "/target", "harness.c", _read_text(HARNESS_C))

        tasks.notify_status(task_id, "DAST", "Running",
                            "Building tcpdump (libnetdissect.a) and compiling harness.c ...")
        res = container.exec_run(["sh", "-c", _BUILD_HARNESS_CMD], user="root")
        if res.exit_code != 0:
            logs = container.exec_run(
                "sh -c 'tail -n 25 /tmp/cc.log /tmp/make.log /tmp/cfg.log 2>/dev/null'", user="root"
            ).output.decode("utf-8", "replace")
            raise Exception(f"debug fallback: known-good harness build failed:\n{logs[-1500:]}")

        # Seed corpus of short, in-bounds packets (clean dry run, fast path to the OOB).
        container.exec_run(["sh", "-c", _SEED_CMD], user="root")

        # Fuzz with retries: each good attempt crashes within seconds; retry the occasional
        # ASAN-nondeterministic forkserver-startup abort instead of failing the pipeline.
        for attempt in range(1, FUZZ_ATTEMPTS + 1):
            tasks.notify_status(
                task_id, "DAST", "Running",
                f"Fuzzing bootp_print with harness.c (attempt {attempt}/{FUZZ_ATTEMPTS}, up to {fuzz_timeout}s) ...",
            )
            container.exec_run(["sh", "-c", _FUZZ_ONE_CMD.format(timeout=fuzz_timeout)], user="root")
            ls = container.exec_run("sh -c 'ls outputs/default/crashes/id:* 2>/dev/null'", user="root")
            crash_files = ls.output.decode("utf-8", "replace").split() if ls.exit_code == 0 else []
            if crash_files:
                crash_data = container.exec_run(["cat", crash_files[0]], user="root").output
                tasks.notify_status(task_id, "DAST", "Success",
                                    f"harness.c fuzzing found a real bootp_print crash ({len(crash_data)} bytes).")
                return crash_data
            fs = container.exec_run("sh -c 'grep -c \"Fork server crashed\" /tmp/fuzz.log 2>/dev/null'", user="root")
            tasks.notify_status(task_id, "DAST", "Warning",
                                f"Fuzz attempt {attempt} produced no crash (forkserver_abort={fs.output.decode().strip()}); retrying.")

        tail = container.exec_run("sh -c 'tail -n 15 /tmp/fuzz.log 2>/dev/null'", user="root").output.decode("utf-8", "replace")
        raise Exception(f"debug fallback: fuzzing produced no crash after {FUZZ_ATTEMPTS} attempts\n{tail[-1000:]}")
    finally:
        try:
            container.stop(timeout=1)
            container.remove(force=True)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Activation: wrap tasks.py boundary functions with real-on-failure fallbacks
# --------------------------------------------------------------------------- #
def activate() -> None:
    """Monkeypatch tasks.py's boundary functions so each real stage has a real fallback on
    failure. Idempotent; a no-op unless DEBUG_TEST_TCPDUMP is set."""
    if not is_enabled():
        return
    import tasks

    if getattr(tasks, "_tcpdump_debug_active", False):
        return
    tasks._tcpdump_debug_active = True

    _orig_clone = tasks.clone_repo
    _orig_codeql = tasks.run_codeql_analysis
    _orig_dast = tasks.run_dast_fuzzing
    _orig_llm = tasks.call_llm_api

    def clone_repo(task_id, repo_url, temp_dir):
        try:
            return _orig_clone(task_id, repo_url, temp_dir)
        except Exception as e:
            tasks.notify_status(task_id, "INIT", "Warning", f"git clone failed ({e}); continuing with tcpdump debug fallback.")

    def run_codeql_analysis(task_id, temp_dir, db_path, sarif_path, callgraph_sarif_path):
        try:
            return _orig_codeql(task_id, temp_dir, db_path, sarif_path, callgraph_sarif_path)
        except Exception as e:
            tasks.notify_status(task_id, "SAST", "Warning", f"CodeQL failed ({e}); using real tcpdump bootp_sa.sarif.")
            shutil.copyfile(BOOTP_SARIF, sarif_path)

    def run_dast_fuzzing(task_id, repo_url, repo_path, harness_code, harness_path):
        try:
            return _orig_dast(task_id, repo_url, repo_path, harness_code, harness_path)
        except Exception as e:
            # LLM harness failed to build/fuzz -> fall back to the known-good harness.c and
            # fuzz for real (no canned crash).
            tasks.notify_status(task_id, "DAST", "Warning", f"LLM-harness DAST failed ({e}).")
            return fuzz_known_good_harness(task_id, repo_url)

    def call_llm_api(prompt, model="gemini-2.5-flash", task_type=None):
        try:
            resp = _orig_llm(prompt, model=model, task_type=task_type)
        except Exception as e:
            resp = f"ERROR: {e}"
        if not resp or resp.startswith("ERROR"):
            if task_type == "harness" or "Write a complete C harness" in prompt or "Fix the errors based on the compiler output" in prompt:
                return _read_text(HARNESS_C)
            if task_type == "patch" or "Fix the vulnerability in this code" in prompt:
                return _read_text(MOCK_PATCH_C)
            if task_type == "docker_deps" or "configuring an AFL++ fuzzing environment" in prompt:
                # Default apt deps for building tcpdump-4.9.1 (libpcap + openssl/crypto).
                return "libpcap-dev libssl-dev pkg-config zlib1g-dev"
        return resp

    tasks.clone_repo = clone_repo
    tasks.run_codeql_analysis = run_codeql_analysis
    tasks.run_dast_fuzzing = run_dast_fuzzing
    tasks.call_llm_api = call_llm_api


# Auto-activate when imported under the flag (e.g. celery `--include=debug_tcpdump`).
activate()
