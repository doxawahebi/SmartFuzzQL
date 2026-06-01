from celery import Celery
import collections
import queue
import threading
import time
import tempfile
import shutil
import redis
from rich.console import Console
from rich.markup import escape
from google import genai
import os
import json
import subprocess
import docker
import requests
import io
import sys
import tarfile
from datetime import datetime

# Ensure this backend directory is importable by absolute path. The Celery worker's
# sys.path[0] is '' (relative to cwd), so the lazy `from database import ...` /
# `from models import ...` in run_pipeline can fail with ModuleNotFoundError once the
# working directory changes during a job. Pinning the dir keeps those imports reliable.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import patching  # noqa: E402  (after sys.path pin so the sibling module always resolves)

# Pre-load the DB modules in the worker MainProcess so they live in sys.modules and the
# lazy `from database import ...` inside the task is fully independent of cwd/sys.path in
# forked children. Guarded so tasks.py still imports where the DB stack is unavailable
# (e.g. unit tests without psycopg2).
try:  # noqa: SIM105
    import database  # noqa: F401
    import models  # noqa: F401
except Exception:
    pass

console = Console()
redis_client = redis.Redis.from_url(
    os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
)

celery_app = Celery(
    "hast_pipeline",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
)

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
ALLOWED_GEMINI_MODELS = [
    "gemini-2.5-flash",
    "gemini-3-flash-preview",
    "gemini-3.5-flash",
]
DEV_LLM_CONFIG_KEY = "dev:llm_config"
SAMPLE_REPOS = {
    "sample://buffer-overflow": {
        "name": "Buffer Overflow Sample",
        "description": "Tiny C project with argv/input taint reaching strcpy.",
        "path": os.path.join(_BACKEND_DIR, "debug_samples", "buffer_overflow_repo"),
    }
}


class PipelineUserError(RuntimeError):
    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


def is_sample_repo_url(repo_url: str) -> bool:
    return repo_url in SAMPLE_REPOS


def copy_sample_repo(repo_url: str, target_dir: str):
    sample = SAMPLE_REPOS.get(repo_url)
    if not sample:
        raise ValueError(f"Unknown sample repository: {repo_url}")
    sample_path = sample["path"]
    if not os.path.isdir(sample_path):
        raise FileNotFoundError(f"Sample repository is missing: {sample_path}")
    shutil.copytree(sample_path, target_dir, dirs_exist_ok=True)


def notify_status(task_id, step, status, details=None, extra=None):
    # Rich print for CMD logs
    color = "green" if status == "Success" else "red" if status == "Failed" else "cyan"
    console.print(
        f"[{color}][{step}][/{color}] {status} - {escape(str(details or ''))}"
    )

    # Broadcast to Redis PubSub for WebSockets
    payload = {"task_id": task_id, "step": step, "status": status, "details": details}
    if extra:
        _CORE_KEYS = {"task_id", "step", "status", "details"}
        payload.update({k: v for k, v in extra.items() if k not in _CORE_KEYS})
    message = json.dumps(payload)
    try:
        redis_client.publish("pipeline_logs", message)
    except Exception as e:
        console.print(f"[red]Failed to publish to redis: {e}[/red]")


def copy_text_to_container(container, target_dir: str, filename: str, content: str):
    tar_buffer = io.BytesIO()
    encoded_content = content.encode("utf-8")

    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        tar_info = tarfile.TarInfo(name=filename)
        tar_info.size = len(encoded_content)
        tar_info.mode = 0o644
        tar.addfile(tar_info, io.BytesIO(encoded_content))

    tar_buffer.seek(0)
    container.put_archive(target_dir, tar_buffer.getvalue())


def _extract_taint_path(sarif_result: dict) -> dict:
    """Transform a SARIF result's codeFlows into {nodes, edges} for the report API."""
    code_flows = sarif_result.get("codeFlows", [])
    if not code_flows:
        return {"nodes": [], "edges": []}
    locations = code_flows[0].get("threadFlows", [{}])[0].get("locations", [])
    nodes, edges = [], []
    n = len(locations)
    for i, loc_wrapper in enumerate(locations):
        phys = loc_wrapper.get("location", {}).get("physicalLocation", {})
        region = phys.get("region", {})
        label = (
            loc_wrapper.get("location", {}).get("message", {}).get("text", f"step-{i}")
        )
        role = "source" if i == 0 else ("sink" if i == n - 1 else "intermediate")
        nodes.append(
            {
                "id": f"node-{i}",
                "label": label,
                "role": role,
                "file": phys.get("artifactLocation", {}).get("uri", ""),
                "start_line": region.get("startLine", 0),
                "start_col": region.get("startColumn", 0),
                "end_col": region.get("endColumn", 0),
            }
        )
        if i > 0:
            edges.append(
                {
                    "id": f"edge-{i-1}-{i}",
                    "source": f"node-{i-1}",
                    "target": f"node-{i}",
                }
            )
    return {"nodes": nodes, "edges": edges}


# Dangerous C string sinks (kept in sync with backend/queries/*.ql DangerousFunction).
DANGEROUS_FUNCS = {"strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"}
CALL_EDGE_RULE_ID = "cpp/call-graph-edges"


def _parse_call_edges(sarif_results: list) -> tuple:
    """Parse call_graph.ql results into (edges, locs).

    edges: list of (caller, callee) tuples.
    locs:  dict mapping (caller, callee) -> (file_uri, start_line) of the call site.
    """
    edges, locs = [], {}
    for r in sarif_results:
        if r.get("ruleId") != CALL_EDGE_RULE_ID:
            continue
        text = r.get("message", {}).get("text", "")
        if not text.startswith("CALL_EDGE ") or " -> " not in text:
            continue
        caller, callee = text[len("CALL_EDGE ") :].split(" -> ", 1)
        caller, callee = caller.strip(), callee.strip()
        phys = (r.get("locations", [{}])[0] or {}).get("physicalLocation", {})
        file = phys.get("artifactLocation", {}).get("uri", "")
        line = phys.get("region", {}).get("startLine", 0)
        edges.append((caller, callee))
        locs[(caller, callee)] = (file, line)
    return edges, locs


def _vuln_fn_from_related(vuln_result: dict, callers: set) -> str | None:
    """Best-effort: pull a function name from a finding's relatedLocations that is a
    known caller in the call graph (covers structural queries like bootp_print.ql)."""
    for rel in vuln_result.get("relatedLocations", []) if vuln_result else []:
        name = rel.get("message", {}).get("text", "").strip()
        if name in callers:
            return name
    return None


def _find_vuln_function(
    edges: list, locs: dict, sink_line: int, vuln_result: dict | None
) -> str | None:
    """Identify the function enclosing the sink: the internal function that calls a
    dangerous C function, preferring the call site on the taint sink's line."""
    dangerous_edges = [
        (caller, callee) for (caller, callee) in edges if callee in DANGEROUS_FUNCS
    ]
    if dangerous_edges:
        if sink_line:
            for caller, callee in dangerous_edges:
                if locs.get((caller, callee), ("", 0))[1] == sink_line:
                    return caller
        return dangerous_edges[0][0]
    # Fallback for structural findings without a dangerous-call sink.
    all_fns = {c for c, _ in edges} | {c for _, c in edges}
    return _vuln_fn_from_related(vuln_result, all_fns)


def _call_path_from_chain(chain: list, locs: dict) -> dict:
    """Build {nodes, edges} (taint_path shape) from an ordered list of function names."""
    nodes, out_edges = [], []
    n = len(chain)
    for i, fn in enumerate(chain):
        if i > 0:
            file, line = locs.get((chain[i - 1], fn), ("", 0))
        elif n > 1:
            file, line = locs.get((chain[0], chain[1]), ("", 0))
        else:
            file, line = "", 0
        if n == 1:
            role = "sink"
        else:
            role = "source" if i == 0 else ("sink" if i == n - 1 else "intermediate")
        nodes.append(
            {
                "id": f"call-{i}",
                "label": fn,
                "role": role,
                "file": file,
                "start_line": line,
                "start_col": 0,
                "end_col": 0,
            }
        )
        if i > 0:
            out_edges.append(
                {
                    "id": f"call-edge-{i-1}-{i}",
                    "source": f"call-{i-1}",
                    "target": f"call-{i}",
                }
            )
    return {"nodes": nodes, "edges": out_edges}


def _extract_call_path(
    sarif_results: list,
    vuln_result: dict | None = None,
    sink_line: int = 0,
    entry: str = "main",
) -> dict:
    """BFS the static call graph from `entry` (default main) to the vulnerable function,
    returning the shortest call chain as {nodes, edges} for the report API."""
    edges, locs = _parse_call_edges(sarif_results)
    if not edges:
        return {"nodes": [], "edges": []}
    vuln_fn = _find_vuln_function(edges, locs, sink_line, vuln_result)
    if not vuln_fn:
        return {"nodes": [], "edges": []}

    adj = {}
    for caller, callee in edges:
        adj.setdefault(caller, []).append(callee)

    # BFS for the shortest entry -> vuln_fn chain.
    chain = None
    if entry in adj or entry == vuln_fn:
        queue = collections.deque([[entry]])
        seen = {entry}
        while queue:
            path = queue.popleft()
            if path[-1] == vuln_fn:
                chain = path
                break
            for nxt in adj.get(path[-1], []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(path + [nxt])
    # If the entry can't reach the sink (or there is no entry), show the vuln fn alone.
    if chain is None:
        chain = [vuln_fn]
    return _call_path_from_chain(chain, locs)


def clone_repo(task_id, repo_url, temp_dir):
    """Shallow-clone the target repository into temp_dir. Raises on failure."""
    if is_sample_repo_url(repo_url):
        notify_status(
            task_id,
            "INIT",
            "Running",
            f"Loading internal sample repository {repo_url}",
        )
        copy_sample_repo(repo_url, temp_dir)
        return

    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, temp_dir],
        capture_output=True,
        check=True,
    )


def run_codeql_analysis(task_id, temp_dir, db_path, sarif_path, callgraph_sarif_path):
    """Run the two CodeQL passes: write the vulnerability SARIF to sarif_path and the
    best-effort call-graph SARIF to callgraph_sarif_path. Raises if the vulnerability pass
    cannot run (e.g. the CodeQL CLI is missing)."""
    queries_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "queries")
    # Vulnerability-finding queries and the call-graph query live in separate
    # subdirectories of the same pack so each CodeQL pass runs only its own queries.
    vuln_queries_dir = os.path.join(queries_dir, "vulnerabilities")
    callgraph_queries_dir = os.path.join(queries_dir, "callgraph")
    codeql_threads = os.environ.get("CODEQL_THREADS", "1")
    codeql_ram_mb = os.environ.get("CODEQL_RAM_MB", "2048")

    def run_codeql_streaming(cmd):
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        lines = queue.Queue()

        def read_stdout():
            try:
                for raw_line in proc.stdout:
                    lines.put(raw_line)
            finally:
                lines.put(None)

        reader = threading.Thread(target=read_stdout, daemon=True)
        reader.start()

        started_at = time.time()
        last_output_at = started_at
        last_heartbeat_at = started_at
        command_name = " ".join(cmd[:3])

        while True:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                line = None

            if line is None:
                if proc.poll() is not None:
                    break
                now = time.time()
                if now - last_heartbeat_at >= 15:
                    elapsed = int(now - started_at)
                    quiet_for = int(now - last_output_at)
                    notify_status(
                        task_id,
                        "SAST",
                        "Running",
                        f"{command_name} still running... elapsed={elapsed}s, no new CodeQL output for {quiet_for}s",
                    )
                    last_heartbeat_at = now
                continue

            line = line.rstrip()
            if line:
                notify_status(task_id, "SAST", "Running", line)
                last_output_at = time.time()
                last_heartbeat_at = last_output_at

        proc.wait()
        if proc.returncode != 0:
            if proc.returncode == 137:
                raise PipelineUserError(
                    "CodeQL was killed with exit status 137, which usually means the "
                    "container or WSL host ran out of memory.",
                    "Lower CODEQL_RAM_MB/CODEQL_THREADS, increase Docker/WSL memory, "
                    "or use a lighter dev CodeQL query for sample runs.",
                )
            raise subprocess.CalledProcessError(proc.returncode, cmd)

    run_codeql_streaming(
        [
            "codeql",
            "database",
            "create",
            db_path,
            "--language=cpp",
            f"--source-root={temp_dir}",
            "--build-mode=none",
        ]
    )
    # Resolve query dependencies (codeql/cpp-all powers the DataFlow taint query).
    # Best-effort: if the worker is offline but the lib pack is already on the search
    # path, the analyze step below still succeeds.
    try:
        run_codeql_streaming(["codeql", "pack", "install", queries_dir])
    except subprocess.CalledProcessError as e:
        notify_status(
            task_id,
            "SAST",
            "Warning",
            f"codeql pack install failed; relying on --search-path: {e}",
        )
    # Pass 1 - vulnerability-finding queries only (taint + structural). Raises on failure.
    run_codeql_streaming(
        [
            "codeql",
            "database",
            "analyze",
            db_path,
            vuln_queries_dir,
            "--search-path=/opt/codeql/qlpacks",
            f"--threads={codeql_threads}",
            f"--ram={codeql_ram_mb}",
            "--format=sarif-latest",
            f"--output={sarif_path}",
        ]
    )
    # Pass 2 - call-graph reachability. Supplementary: a failure here must not abort the
    # pipeline, so it runs after the vuln pass and swallows errors.
    try:
        run_codeql_streaming(
            [
                "codeql",
                "database",
                "analyze",
                db_path,
                callgraph_queries_dir,
                "--search-path=/opt/codeql/qlpacks",
                f"--threads={codeql_threads}",
                f"--ram={codeql_ram_mb}",
                "--format=sarif-latest",
                f"--output={callgraph_sarif_path}",
            ]
        )
    except Exception as e:
        notify_status(task_id, "SAST", "Warning", f"Call-graph analysis skipped: {e}")


def run_dast_fuzzing(
    task_id, repo_url, repo_path, harness_code, harness_path, vuln_code=""
):
    """Build a per-job fuzzing image, compile the harness (LLM feedback loop), fuzz with
    AFL++, and return the crash input bytes. Raises on build/compile failure or timeout.
    """
    docker_client = docker.from_env()
    container = None
    try:
        # Call the existing dynamic builder (we invoke it inline because we need the image)
        build_res = build_dynamic_fuzzing_env(repo_url, task_id)
        if build_res["status"] == "Failed":
            raise Exception(f"Failed to build fuzzer env: {build_res.get('error')}")
        image_name = build_res["image"]

        # Run container
        container = docker_client.containers.run(
            image_name,
            command="tail -f /dev/null",
            detach=True,
            working_dir="/target",
            privileged=True,
        )

        # 409 error : Check if container is running
        container.reload()
        console.print(f"Container status: {container.status}")
        if container.status != "running":
            console.print("Container logs:", container.logs().decode("utf-8"))
            raise Exception(
                "\ucee8\ud14c\uc774\ub108\uac00 \uc815\uc0c1\uc801\uc73c\ub85c \uc2e4\ud589\ub418\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4."
            )

        copy_text_to_container(container, "/target", "harness.c", harness_code)

        # Compile harness with feedback loop
        compile_cmd = "afl-clang-fast -fsanitize=address -I/usr/local/include/afl++ -o fuzz_target harness.c"
        max_compile_retries = 3
        compile_success = False

        for attempt in range(1, max_compile_retries + 1):
            notify_status(
                task_id,
                "DAST",
                "Running",
                f"Compiling harness (Attempt {attempt}/{max_compile_retries})...",
            )
            compile_res = container.exec_run(compile_cmd, user="root", demux=True)

            if compile_res.exit_code == 0:
                compile_success = True
                notify_status(
                    task_id, "DAST", "Success", "Harness compiled successfully."
                )
                break

            # When demux=True is set, compile_res.output returns a (stdout_bytes, stderr_bytes) tuple.
            stdout_bytes, stderr_bytes = compile_res.output
            stdout_str = (
                stdout_bytes.decode("utf-8", errors="replace").strip()
                if stdout_bytes
                else "No STDOUT"
            )
            stderr_str = (
                stderr_bytes.decode("utf-8", errors="replace").strip()
                if stderr_bytes
                else "No STDERR"
            )

            error_msg = (
                f"Failed to compile harness!\n"
                f"[Command]  {compile_cmd}\n"
                f"[Exit Code] {compile_res.exit_code}\n"
                f"{'-'*20} STDOUT {'-'*20}\n"
                f"{stdout_str}\n"
                f"{'-'*20} STDERR {'-'*20}\n"
                f"{stderr_str}\n"
                f"{'-'*48}"
            )

            if attempt == max_compile_retries:
                raise Exception(error_msg)
            notify_status(
                task_id,
                "DAST",
                "Warning",
                "Compilation failed. Requesting quick fix from LLM...",
            )
            fix_prompt = f"The following C harness failed to compile. Fix the errors based on the compiler output and return only the corrected complete C code. Do not explain.\n\nCompiler Output:\n{stderr_str}\n\nOriginal Target Source (for correct function signatures):\n```c\n{truncate_for_prompt(vuln_code)}\n```\n\nBroken Harness:\n```c\n{harness_code}\n```"
            fix_resp = call_llm_api(
                fix_prompt, model="gemini-2.5-flash", task_type="harness"
            )
            harness_code = extract_c_code(fix_resp)

            # Update the local file and container
            with open(harness_path, "w") as f:
                f.write(harness_code)
            copy_text_to_container(container, "/target", "harness.c", harness_code)

        if not compile_success:
            raise Exception("Failed to compile harness after maximum retries.")

        TIME_MINITUTE = 1
        POLL_INTERVAL = 10

        # Setup basic inputs and run afl-fuzz
        container.exec_run("mkdir -p inputs outputs", user="root")
        container.exec_run("sh -c 'echo A > inputs/seed'", user="root")
        container.exec_run(
            "sh -c 'echo core > /proc/sys/kernel/core_pattern'", user="root"
        )

        notify_status(
            task_id,
            "DAST",
            "Running",
            f"Starting AFL++ fuzzing... This may take up to {TIME_MINITUTE} minutes. Monitoring for crashes.",
        )
        fuzz_cmd = "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i ./inputs -o ./outputs -m none -- ./fuzz_target > fuzzer_stdout.log 2> fuzzer_stderr.log"
        container.exec_run(f"sh -c '{fuzz_cmd} &'", user="root", detach=True)

        # Read the background process logs to verify it started correctly
        time.sleep(2)
        fuzzer_stdout = container.exec_run("cat fuzzer_stdout.log", user="root")
        fuzzer_stderr = container.exec_run("cat fuzzer_stderr.log", user="root")
        console.print(
            f"[DEBUG] AFL++ STDOUT:\n{fuzzer_stdout.output.decode('utf-8', errors='replace')}"
        )
        console.print(
            f"[DEBUG] AFL++ STDERR:\n{fuzzer_stderr.output.decode('utf-8', errors='replace')}"
        )

        notify_status(
            task_id,
            "DAST",
            "Running",
            f"Fuzzer started. Polling for crashes every {POLL_INTERVAL} seconds...",
        )

        # Poll for the configured timeout
        timeout = TIME_MINITUTE * 60
        start = time.time()
        crash_found = False
        crash_data = None

        while time.time() - start < timeout:
            console.print(
                f"[DEBUG] Polling loop running... Elapsed: {time.time() - start:.1f}s"
            )
            stats = container.exec_run("cat outputs/default/fuzzer_stats", user="root")
            if stats.exit_code == 0:
                stats_str = stats.output.decode("utf-8")
                afl_stats = {}
                for line in stats_str.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        afl_stats[k.strip()] = v.strip()
                elapsed_sec = 0
                raw_time = afl_stats.get("run_time", "0")
                try:
                    elapsed_sec = int(raw_time.split()[0])
                except (ValueError, IndexError):
                    pass
                try:
                    execs = int(afl_stats.get("execs_done", "0") or "0")
                    crashes = int(afl_stats.get("unique_crashes", "0") or "0")
                except ValueError:
                    execs = 0
                    crashes = 0
                notify_status(
                    task_id,
                    "DAST",
                    "Running",
                    f"Fuzzer running... Stats:\n{stats_str[:200]}...",
                    extra={
                        "fuzz_stats": {
                            "time_sec": elapsed_sec,
                            "execs": execs,
                            "crashes": crashes,
                        }
                    },
                )
            else:
                # No stats file yet
                console.print(
                    f"[DEBUG] fuzzer_stats not found yet. Exit code: {stats.exit_code}"
                )

            crashes = container.exec_run(
                "sh -c 'ls outputs/default/crashes/id:* 2>/dev/null'", user="root"
            )
            if crashes.exit_code == 0 and crashes.output.decode("utf-8").strip():
                crash_found = True
                crash_files = crashes.output.decode("utf-8").strip().split()
                if crash_files:
                    crash_content = container.exec_run(
                        f"cat {crash_files[0]}", user="root"
                    )
                    crash_data = crash_content.output
                notify_status(task_id, "DAST", "Success", "Crash found!")
                break
            time.sleep(POLL_INTERVAL)

        if not crash_found:
            notify_status(task_id, "DAST", "Failed", "No crash found within timeout")
            raise Exception("Timeout reached without finding crash")
        return crash_data
    finally:
        if container:
            try:
                container.stop(timeout=1)
                container.remove(force=True)
            except Exception as e:
                console.print(f"[red]Failed to cleanup container: {e}[/red]")


@celery_app.task(bind=True)
def run_pipeline(self, repo_url: str):
    return _run_pipeline_impl(self.request.id, repo_url)


def _run_pipeline_impl(task_id: str, repo_url: str):
    temp_dir = tempfile.mkdtemp(prefix=f"pipeline_run_{task_id}_")
    console.print(f"temp_dir : {temp_dir}")
    try:
        notify_status(
            task_id,
            "INIT",
            "Running",
            f"Starting pipeline for {repo_url} in {temp_dir}",
        )
        clone_repo(task_id, repo_url, temp_dir)
        repo_path = temp_dir

        # Step 1: SAST (CodeQL)
        notify_status(
            task_id,
            "SAST",
            "Running",
            "Cloning and extracting source-level logical vulnerabilities via CodeQL",
        )
        db_path = os.path.join(temp_dir, "my-db")
        sarif_path = os.path.join(temp_dir, "results.sarif")
        callgraph_sarif_path = os.path.join(temp_dir, "callgraph.sarif")
        run_codeql_analysis(
            task_id, temp_dir, db_path, sarif_path, callgraph_sarif_path
        )

        with open(sarif_path, "r") as f:
            sarif_data = json.load(f)

        # Load call-graph edges from the separate pass (best-effort; may be absent).
        call_edge_results = []
        if os.path.exists(callgraph_sarif_path):
            try:
                with open(callgraph_sarif_path, "r") as f:
                    call_edge_results = (
                        json.load(f).get("runs", [{}])[0].get("results", [])
                    )
            except (json.JSONDecodeError, OSError) as e:
                notify_status(
                    task_id, "SAST", "Warning", f"Could not read call-graph SARIF: {e}"
                )

        vuln_msg = "Unknown vulnerability"
        vuln_file = "unknown"
        vuln_line = None
        all_results = sarif_data.get("runs", [{}])[0].get("results", [])
        # The vuln pass no longer emits call edges, but filter defensively in case the
        # pack layout changes and both query sets land in one SARIF.
        results = [r for r in all_results if r.get("ruleId") != CALL_EDGE_RULE_ID]
        console.print(f"results : {results}")
        if results:
            vuln_msg = results[0].get("message", {}).get("text", "")
            console.print(f"vuln_msg : {vuln_msg}")
            locations = results[0].get("locations", [])
            console.print(f"locations : {locations}")
            if locations:
                physical = locations[0].get("physicalLocation", {})
                vuln_file = physical.get("artifactLocation", {}).get("uri", "")
                # Sink line drives the function-scoped patch (see backend/patching.py).
                vuln_line = physical.get("region", {}).get("startLine")

        vuln_file_full = os.path.join(repo_path, vuln_file)
        console.print(f"vuln_file_full: {vuln_file_full}")
        vuln_code = "Code not found 243234234234234234"
        if os.path.exists(vuln_file_full):
            with open(vuln_file_full, "r") as f:
                vuln_code = f.read()
        console.print(f"vuln_code : {vuln_code}")

        notify_status(
            task_id,
            "SAST",
            "Success",
            f"Found vulnerability: {vuln_msg} in {vuln_file}",
            extra={
                "vuln": {
                    "message": vuln_msg,
                    "file": vuln_file,
                    "code_snippet": (
                        vuln_code[:500]
                        if vuln_code != "Code not found 243234234234234234"
                        else None
                    ),
                }
            },
        )

        # Step 2: AI Harness Generation
        notify_status(
            task_id,
            "AI_HARNESS",
            "Running",
            "Requesting source-code level C harness from LLM",
        )
        vuln_code_ctx = truncate_for_prompt(vuln_code)
        prompt = (
            f"Write a complete C harness for AFL++ persistent mode targeting the function(s) in this file: {vuln_file}.\n"
            f"Use __AFL_FUZZ_INIT(), a `while (__AFL_LOOP(1000))` loop, and read the test case from "
            f"__AFL_FUZZ_TESTCASE_BUF / __AFL_FUZZ_TESTCASE_LEN. Define your own `int main()` "
            f"(do NOT define LLVMFuzzerTestOneInput). Call the vulnerable function so the crash is reachable.\n"
            f"Vulnerability: {vuln_msg}\n"
            f"Source Code:\n```c\n{vuln_code_ctx}\n```\n"
            f"Return ONLY the complete C harness inside a single ```c code block. Do not explain."
        )
        llm_resp = call_llm_api(prompt, model="gemini-2.5-flash", task_type="harness")
        harness_code = extract_c_code(llm_resp)
        harness_path = os.path.join(repo_path, "harness.c")
        console.print(f"harness_path : {harness_path}")
        console.print(f"harness_code : {harness_code}")
        with open(harness_path, "w") as f:
            f.write(harness_code)

        # Step 3: DAST (AFL++)
        notify_status(
            task_id,
            "DAST",
            "Running",
            "Fuzzing via isolated container against generated harness (max 20 mins)",
        )
        crash_data = run_dast_fuzzing(
            task_id, repo_url, repo_path, harness_code, harness_path, vuln_code
        )

        # Step 4: AI Patch Generation
        notify_status(
            task_id,
            "AI_PATCH",
            "Running",
            "Crash verified. Querying LLM for source-code secure patch",
        )
        # Feed the LLM the enclosing vulnerable function (not a blind file-head truncation,
        # which for large targets never contains the sink) so the patch is grounded in the
        # real vulnerable code. Splice the patched function back into the full file so the
        # stored diff is minimal and aligned, and the SARIF line numbers still match.
        crash_hex = crash_data.hex() if crash_data else None
        vuln_function = patching.extract_vulnerable_function(vuln_code, vuln_line)
        patch_snippet = vuln_function or patching.truncate_for_prompt(vuln_code)
        patch_prompt = patching.build_patch_prompt(patch_snippet, vuln_msg, crash_hex)
        patch_resp = call_llm_api(
            patch_prompt, model="gemini-2.5-flash", task_type="patch"
        )
        patched_function = extract_c_code(patch_resp)
        if vuln_function:
            patch_code = patching.splice_patch(vuln_code, vuln_line, patched_function)
        else:
            patch_code = patched_function
        patch_path = os.path.join(repo_path, "patched_" + os.path.basename(vuln_file))
        with open(patch_path, "w") as f:
            f.write(patch_code)

        # Step 5: DB Storage
        notify_status(
            task_id,
            "DB_STORAGE",
            "Running",
            "Storing vulnerability, harness, fuzzer trace, and patches in PostgreSQL",
        )
        try:
            from database import SessionLocal
            from models import Job as JobModel

            db = SessionLocal()
            try:
                job_row = db.query(JobModel).filter(JobModel.task_id == task_id).first()
                if job_row:
                    job_row.state = "SUCCESS"
                    job_row.completed_at = datetime.utcnow()
                    job_row.vuln_message = vuln_msg
                    job_row.vuln_file = vuln_file
                    job_row.code_snippet = (
                        vuln_code[:500]
                        if vuln_code != "Code not found 243234234234234234"
                        else None
                    )
                    job_row.original_code = (
                        vuln_code
                        if vuln_code != "Code not found 243234234234234234"
                        else None
                    )
                    # Prefer the finding that carries a data-flow path (codeFlows).
                    taint_result = next(
                        (r for r in results if r.get("codeFlows")),
                        results[0] if results else None,
                    )
                    taint_path = (
                        _extract_taint_path(taint_result)
                        if taint_result
                        else {"nodes": [], "edges": []}
                    )
                    sink_line = (
                        taint_path["nodes"][-1]["start_line"]
                        if taint_path["nodes"]
                        else 0
                    )
                    job_row.taint_path = taint_path
                    job_row.call_path = _extract_call_path(
                        call_edge_results, vuln_result=taint_result, sink_line=sink_line
                    )
                    job_row.patch_generated = True
                    job_row.crash_hex = crash_data.hex() if crash_data else None
                    job_row.patch_code = patch_code
                    db.commit()
                notify_status(
                    task_id, "DB_STORAGE", "Success", "Results stored in PostgreSQL"
                )
            except Exception as db_err:
                db.rollback()
                notify_status(
                    task_id, "DB_STORAGE", "Warning", f"DB write failed: {db_err}"
                )
            finally:
                db.close()
        except ImportError as imp_err:
            notify_status(
                task_id,
                "DB_STORAGE",
                "Warning",
                f"Database module unavailable, skipping storage: {imp_err!r}",
            )

        notify_status(
            task_id,
            "PIPELINE",
            "Success",
            "Pipeline completely executed.",
            extra={
                "result": {
                    "repo": repo_url,
                    "vuln_msg": vuln_msg,
                    "vuln_file": vuln_file,
                    "patch_generated": True,
                    "crash_hex": crash_data.hex() if crash_data else None,
                    "patch_code": patch_code,
                }
            },
        )
        return {"status": "Complete", "repo": repo_url, "patch_generated": True}

    except Exception as e:
        extra = None
        if isinstance(e, PipelineUserError):
            extra = {"error_hint": e.hint}
        notify_status(task_id, "PIPELINE", "Failed", str(e), extra=extra)
        try:
            from database import SessionLocal
            from models import Job as JobModel

            db = SessionLocal()
            try:
                job_row = db.query(JobModel).filter(JobModel.task_id == task_id).first()
                if job_row:
                    job_row.state = "FAILURE"
                    job_row.completed_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()
        except ImportError:
            pass
        raise e
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def truncate_for_prompt(text, max_chars=3000):
    """Cap source code interpolated into an LLM prompt so large files don't blow the
    context window (mirrors the build-context truncation in build_dynamic_fuzzing_env).
    """
    if text and len(text) > max_chars:
        return text[:max_chars] + "\n...[TRUNCATED]..."
    return text


def extract_c_code(llm_response):
    if "```c" in llm_response:
        start = llm_response.find("```c") + 4
        end = llm_response.find("```", start)
        return llm_response[start:end].strip()
    elif "```" in llm_response:
        start = llm_response.find("```") + 3
        end = llm_response.find("```", start)
        return llm_response[start:end].strip()
    return llm_response.strip()


def _get_dev_llm_config() -> dict:
    try:
        raw = redis_client.get(DEV_LLM_CONFIG_KEY)
    except Exception:
        return {}
    if not raw:
        return {}
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def call_llm_api(prompt, model="gemini-2.5-flash", task_type=None):
    dev_config = _get_dev_llm_config()
    bypass_llm = (
        os.environ.get("DEBUG_BYPASS_LLM", "False").lower() in ("true", "1", "yes")
        or str(dev_config.get("bypass_llm", "False")).lower() in ("true", "1", "yes")
    )
    if bypass_llm:
        debug_assets_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "debug_assets"
        )

        if task_type == "harness":
            mock_file = os.path.join(debug_assets_dir, "mock_harness.c")
            if not os.path.exists(mock_file):
                console.print(f"[red][DEBUG] {mock_file} not found[/red]")
                raise Exception(f"[DEBUG] {mock_file} not found")
            with open(mock_file, "r") as f:
                return f.read()

        elif task_type == "patch":
            mock_file = os.path.join(debug_assets_dir, "mock_patch.c")
            if not os.path.exists(mock_file):
                console.print(f"[red][DEBUG] {mock_file} not found[/red]")
                raise Exception(f"[DEBUG] {mock_file} not found")
            with open(mock_file, "r") as f:
                return f.read()

        elif task_type == "docker_deps":
            mock_file = os.path.join(debug_assets_dir, "mock_deps.txt")
            if os.path.exists(mock_file):
                with open(mock_file, "r") as f:
                    return f.read()
            return "pkg-config libssl-dev zlib1g-dev"

    selected_model = dev_config.get("model") or os.environ.get("GEMINI_MODEL") or model
    if selected_model not in ALLOWED_GEMINI_MODELS:
        selected_model = model if model in ALLOWED_GEMINI_MODELS else DEFAULT_GEMINI_MODEL

    api_key = dev_config.get("api_key") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "ERROR: GEMINI_API_KEY not set"
    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model=selected_model,
            contents=prompt,
        )
        text = response.text
        if text is None:
            return "ERROR: LLM returned empty response (possibly blocked by safety filters)"
        return text
    except Exception as e:
        return f"ERROR: {e}"


def extract_dockerfile(text):
    if "```dockerfile" in text.lower():
        start = text.lower().find("```dockerfile") + 13
        end = text.find("```", start)
        return text[start:end].strip()
    return text.strip()


# def build_dynamic_fuzzing_env(repo_url: str, task_id: str):
@celery_app.task(bind=True)
def build_dynamic_fuzzing_env(self, repo_url: str, task_id: str):
    notify_status(
        task_id,
        "ENV_GEN",
        "Running",
        f"Analyzing target repository {repo_url} for build dependencies",
    )

    # 1. Target Analysis & Build Context Setup
    build_dir = tempfile.mkdtemp(prefix="docker_build_")
    if is_sample_repo_url(repo_url):
        try:
            copy_sample_repo(repo_url, build_dir)
        except Exception as e:
            notify_status(
                task_id, "ENV_GEN", "Failed", f"Failed to load sample repository: {e}"
            )
            shutil.rmtree(build_dir, ignore_errors=True)
            return {"status": "Failed", "error": f"Sample load failed: {e}"}
    else:
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, build_dir],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            notify_status(
                task_id, "ENV_GEN", "Failed", f"Failed to clone repository: {e.stderr}"
            )
            shutil.rmtree(build_dir, ignore_errors=True)
            return {"status": "Failed", "error": f"Clone failed: {e.stderr}"}

    build_context = ""
    critical_files = [
        "README.md",
        "configure",
        "configure.ac",
        "CMakeLists.txt",
        "Makefile",
        "autogen.sh",
    ]
    for file_name in critical_files:
        file_path = os.path.join(build_dir, file_name)
        if os.path.exists(file_path):
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                # Trucate to avoid massive context
                if len(content) > 3000:
                    content = content[:3000] + "\n...[TRUNCATED]..."
                build_context += f"\n--- {file_name} ---\n{content}\n"

    max_retries = 3
    feedback_context = []

    # Locate templates in the backend directory
    # TODO : save dynamic-fuzzer.Dockerfile in DB.
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(backend_dir, "Dockerfile.template")
    workspace_dockerfile_path = os.path.join(
        os.path.dirname(backend_dir), "dynamic-fuzzer.Dockerfile"
    )

    try:
        with open(template_path, "r") as f:
            template_content = f.read()
    except FileNotFoundError:
        notify_status(task_id, "ENV_GEN", "Failed", "Dockerfile.template not found.")
        shutil.rmtree(build_dir, ignore_errors=True)
        return {"status": "Failed", "error": "Dockerfile.template missing"}

    for attempt in range(1, max_retries + 1):
        notify_status(
            task_id,
            "ENV_GEN",
            "Running",
            f"Generating dependencies via LLM (Attempt {attempt}/{max_retries})",
        )

        # 2. Dependency Resolution via LLM
        if is_sample_repo_url(repo_url):
            llm_response = "pkg-config"
        else:
            prompt = f"""
You are an expert DevSecOps engineer configuring an AFL++ fuzzing environment on Ubuntu 22.04.
Analyze the target repository's build files and determine its system dependencies (e.g., libpcap-dev, libssl-dev, pkg-config).

Project Repository: {repo_url}
Build Files Context:
{build_context}

Output ONLY a space-separated list of required Ubuntu `apt` packages. 
DO NOT include commands like `apt-get install` or any markdown formatting.
Just the package names, for example: pkg-config libssl-dev zlib1g-dev
"""
            if feedback_context:
                prompt += "\n\nPrevious build attempts failed with these errors. Please fix/add the missing dependencies:\n"
                for fb in feedback_context:
                    prompt += f"{fb}\n"

            llm_response = call_llm_api(prompt, task_type="docker_deps")

        # Clean the response to ensure only space-separated packages are present
        target_deps = (
            llm_response.replace("```dockerfile", "")
            .replace("```", "")
            .replace("\n", " ")
            .strip()
        )

        if "ERROR" in target_deps:
            notify_status(task_id, "ENV_GEN", "Failed", f"LLM Error: {target_deps}")
            shutil.rmtree(build_dir, ignore_errors=True)
            return {"status": "Failed", "error": target_deps}

        # 3. Dockerfile Injection
        dockerfile_content = template_content.replace("{{ TARGET_DEPS }}", target_deps)

        # Save to Workspace Dockerfile explicitly for user review if needed
        with open(workspace_dockerfile_path, "w") as f:
            f.write(dockerfile_content)

        notify_status(
            task_id,
            "ENV_GEN",
            "Running",
            f"Building Docker orchestrator locally... Injecting: {target_deps}",
        )
        build_process = subprocess.run(
            [
                "docker",
                "build",
                "-f",
                workspace_dockerfile_path,
                "-t",
                f"dynamic-fuzzer-{task_id}",
                build_dir,
            ],
            capture_output=True,
            text=True,
        )

        if build_process.returncode == 0:
            notify_status(
                task_id,
                "ENV_GEN",
                "Success",
                "Docker image built successfully with AFL instrumentation!",
            )
            shutil.rmtree(build_dir, ignore_errors=True)
            return {"status": "Success", "image": f"dynamic-fuzzer-{task_id}"}
        else:
            # 4. Build Error Feedback Loop
            notify_status(
                task_id,
                "ENV_GEN",
                "Running",
                f"Docker build failed. Collecting error logs for LLM correction...",
            )
            error_log = build_process.stderr
            console.print(f"[red]Docker Build Error:[/red] {error_log[:1000]}")
            # Truncate very long build logs
            if len(error_log) > 2000:
                error_log = "..." + error_log[-2000:]

            feedback_context.append(
                f"Attempt {attempt} failed.\nDeps Used: {target_deps}\n\nBuild Error:\n{error_log}"
            )

    notify_status(
        task_id,
        "ENV_GEN",
        "Failed",
        f"Failed to build Dockerfile after {max_retries} attempts.",
    )
    shutil.rmtree(build_dir, ignore_errors=True)
    return {"status": "Failed", "error": "Max retries exceeded"}
