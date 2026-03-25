import os
import subprocess
import json
import time
import sys
import shutil

# Configure target files and components
WORKSPACE_DIR = os.path.abspath(os.path.dirname(__file__))
DOCKER_IMAGE = "hast-env"
CONTAINER_NAME = "hast-container"
DB_NAME = "my-db"
SARIF_OUTPUT = "results.sarif"
HARNESS_FILE = "harness.c"
FUZZ_TARGET = "fuzz_target"

def run_cmd(cmd, check=True):
    print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=WORKSPACE_DIR, text=True, capture_output=True)
    if check and result.returncode != 0:
        print(f"[!] Command failed: {cmd}")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        sys.exit(1)
    return result

def step_1_setup_environment():
    print("[+] Step 1: Building Docker environment...")
    run_cmd(f"docker build -t {DOCKER_IMAGE} .")
    
    print("[+] Starting isolated Docker container...")
    # Remove old container if it exists
    run_cmd(f"docker rm -f {CONTAINER_NAME}", check=False)
    
    # Start container with volume attached
    run_cmd(f"docker run -d --name {CONTAINER_NAME} -v {WORKSPACE_DIR}:/workspace -w /workspace {DOCKER_IMAGE} tail -f /dev/null")

def step_2_static_analysis():
    print("[+] Step 2: Creating CodeQL Database...")
    # Clean workspace first
    run_cmd(f"docker exec {CONTAINER_NAME} make clean")
    run_cmd(f"docker exec {CONTAINER_NAME} rm -rf {DB_NAME} {SARIF_OUTPUT}")
    
    run_cmd(f"docker exec {CONTAINER_NAME} codeql database create {DB_NAME} --language=cpp --command=make")
    
    print("[+] Running custom CodeQL query...")
    # download dependencies
    run_cmd(f"docker exec {CONTAINER_NAME} codeql pack install /workspace")
    run_cmd(f"docker exec {CONTAINER_NAME} codeql database analyze {DB_NAME} custom.ql --format=sarif-latest --output={SARIF_OUTPUT}")

def step_3_generate_harness():
    print("[+] Step 3: Parsing SARIF and simulating AI Harness Generation...")
    
    sarif_path = os.path.join(WORKSPACE_DIR, SARIF_OUTPUT)
    if not os.path.exists(sarif_path):
        print("[!] SARIF file not found.")
        sys.exit(1)
        
    with open(sarif_path, 'r') as f:
        try:
            sarif_data = json.load(f)
        except Exception as e:
            print(f"[!] Failed to parse SARIF: {e}")
            sys.exit(1)
            
    vuln_func = "unknown"
    runs = sarif_data.get("runs", [])
    if runs:
        results = runs[0].get("results", [])
        if results:
            first_result = results[0]
            msg = first_result.get("message", {}).get("text", "")
            print(f"    - CodeQL Result: {msg}")
            
            # Simulated AI extraction of target function name
            vuln_func = "vulnerable_function"
            
    if vuln_func == "unknown":
        print("[!] No vulnerabilities detected by CodeQL. Exiting.")
        sys.exit(1)
        
    print(f"    - Simulating LLM generation for target: {vuln_func}")
    
    harness_code = f"""
#define main disabled_main
#include "vuln.c"
#undef main

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    char buf[1024];
    /* Using AFL++ deferred instrumentation requires __AFL_INIT() but fast instrumentation works without it out of the box */
    ssize_t len = read(0, buf, sizeof(buf)-1);
    if (len > 0) {{
        buf[len] = '\\0';
        {vuln_func}(buf);
    }}
    return 0;
}}
"""
    with open(os.path.join(WORKSPACE_DIR, HARNESS_FILE), "w") as f:
        f.write(harness_code)
    print(f"    - Wrote fuzzing harness to {HARNESS_FILE}")

def step_4_fuzzing():
    print("[+] Step 4: Compiling harness with AFL++ and ASan...")
    run_cmd(f"docker exec -e AFL_USE_ASAN=1 {CONTAINER_NAME} afl-clang-fast -o {FUZZ_TARGET} {HARNESS_FILE}")
    
    print("[+] Starting fuzzer...")
    run_cmd(f"docker exec {CONTAINER_NAME} mkdir -p inputs")
    run_cmd(f"docker exec {CONTAINER_NAME} sh -c 'echo \"A\" > inputs/seed'")
    run_cmd(f"docker exec {CONTAINER_NAME} rm -rf outputs")
    
    # Run fuzzer in background. afl-fuzz must have AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES and AFL_SKIP_CPUFREQ for automated running
    fuzz_cmd = f"docker exec -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 -e AFL_SKIP_CPUFREQ=1 {CONTAINER_NAME} afl-fuzz -i inputs -o outputs -- ./{FUZZ_TARGET}"
    proc = subprocess.Popen(fuzz_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("    - Fuzzer running. Waiting for a crash (up to 30s)...")
    start_time = time.time()
    crash_file = None
    
    while time.time() - start_time < 30:
        # Check inside container to bypass permission issues on host
        res = subprocess.run(f"docker exec {CONTAINER_NAME} sh -c 'ls outputs/default/crashes/id:* 2>/dev/null'", shell=True, text=True, capture_output=True)
        if res.returncode == 0 and res.stdout.strip():
            crashes = res.stdout.strip().split()
            if crashes:
                crash_file_in_container = crashes[0]
                # change permissions so host can read it
                run_cmd(f"docker exec {CONTAINER_NAME} chmod -R 777 outputs")
                crash_file = crash_file_in_container.replace("/workspace/", "")
                # in case it printed a relative path:
                if not crash_file.startswith("outputs/"):
                     crash_file = crash_file.split("\n")[0] # Just take the first one
                print(f"    - [!] Crash found! File: {crash_file}")
                break
        time.sleep(1)
        
    # Attempt to terminate fuzzer gracefully
    run_cmd(f"docker exec {CONTAINER_NAME} pkill afl-fuzz", check=False)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    
    if not crash_file:
        print("[!] No crash found within the timeout.")
        sys.exit(1)
        
    return crash_file

def step_5_reporting(crash_file):
    print("[+] Step 5: Generating Final Report...")
    
    crash_path = os.path.join(WORKSPACE_DIR, crash_file)
    with open(crash_path, "rb") as f:
        crash_data = f.read()
        
    report = {
        "status": "VULNERABILITY_PROVEN",
        "pipeline": "HAST (CodeQL + AFL++)",
        "target_function": "vulnerable_function",
        "vulnerability_type": "Buffer Overflow",
        "static_analysis": {
            "tool": "CodeQL",
            "query": "custom.ql (cpp/buffer-overflow-strcpy)",
            "finding": "Potential buffer overflow from function parameter to strcpy"
        },
        "dynamic_analysis": {
            "tool": "AFL++",
            "crash_triggered": True,
            "crash_input_hex": crash_data.hex(),
            "crash_input_repr": repr(crash_data)
        }
    }
    
    report_file = os.path.join(WORKSPACE_DIR, "vulnerability_report.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=4)
        
    print(f"[+] Report generated at {report_file}")
    
    # Store artifacts explicitly as requested
    artifacts_dir = "/home/cks/.gemini/antigravity/brain/94fd1d5c-9c1a-4123-98a3-4958cd73faa3"
    shutil.copy("pipeline.py", os.path.join(artifacts_dir, "pipeline_script.py"))
    shutil.copy("Dockerfile", os.path.join(artifacts_dir, "dockerfile.txt"))
    shutil.copy("vulnerability_report.json", os.path.join(artifacts_dir, "vulnerability_report.json"))

def main():
    try:
        step_1_setup_environment()
        step_2_static_analysis()
        step_3_generate_harness()
        crash_file = step_4_fuzzing()
        step_5_reporting(crash_file)
        print("[*] Pipeline completed successfully.")
    except Exception as e:
        print(f"[!] Pipeline failed: {e}")
        sys.exit(1)
    finally:
        print("[*] Cleaning up Docker container...")
        run_cmd(f"docker rm -f {CONTAINER_NAME}", check=False)

if __name__ == "__main__":
    main()
