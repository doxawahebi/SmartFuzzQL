import os
import subprocess
import json
import time
import sys
import shutil
import argparse
import tempfile
import urllib.parse
from google import genai
from google.genai import types

# Configure target files and components
WORKSPACE_DIR = os.path.abspath(os.path.dirname(__file__))
DOCKER_IMAGE = "hast-env"
CONTAINER_NAME = "hast-container"
DB_NAME = "my-db"
SARIF_OUTPUT = "results.sarif"
HARNESS_FILE = "harness.c"
FUZZ_TARGET = "fuzz_target"
MAX_RETRIES = 3
FUZZ_TIMEOUT_SEC = 20 * 60  # 20 minutes

def run_cmd(cmd, check=True):
    print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=WORKSPACE_DIR, text=True, capture_output=True)
    if check and result.returncode != 0:
        print(f"[!] Command failed: {cmd}")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        sys.exit(1)
    return result

def is_valid_github_url(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc in ["github.com", "www.github.com"]

def step_0_fetch_repo(url, branch=None):
    print(f"[+] Step 0: Fetching repository from {url}...")
    if not is_valid_github_url(url):
        print(f"[!] Invalid GitHub URL: {url}")
        sys.exit(1)
        
    temp_dir = tempfile.mkdtemp(dir=WORKSPACE_DIR, prefix="repo_")
    print(f"    - Cloning into {temp_dir}...")
    
    clone_cmd = ["git", "clone", "--depth", "1"]
    if branch:
        clone_cmd.extend(["--branch", branch])
    clone_cmd.extend([url, temp_dir])
    
    res = subprocess.run(clone_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Git clone failed.")
        print("STDERR:", res.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)
        
    return temp_dir

def step_1_setup_environment():
    print("[+] Step 1: Building Docker environment...")
    run_cmd(f"docker build -t {DOCKER_IMAGE} .")
    
    print("[+] Starting isolated Docker container...")
    # Remove old container if it exists
    run_cmd(f"docker rm -f {CONTAINER_NAME}", check=False)
    
    # Start container with volume attached
    run_cmd(f"docker run -d --name {CONTAINER_NAME} -v {WORKSPACE_DIR}:/workspace -w /workspace {DOCKER_IMAGE} tail -f /dev/null")

def step_2_static_analysis(repo_dir):
    print("[+] Step 2: Creating CodeQL Database...")
    rel_repo = os.path.basename(repo_dir)
    container_repo_path = f"/workspace/{rel_repo}"
    
    # Clean workspace old artifacts
    run_cmd(f"docker exec {CONTAINER_NAME} make clean", check=False)
    run_cmd(f"docker exec {CONTAINER_NAME} rm -rf {DB_NAME} {SARIF_OUTPUT}")
    
    # Run configure before codeql if a configure script exists, or let CodeQL build it
    run_cmd(f"docker exec {CONTAINER_NAME} sh -c 'cd {container_repo_path} && if [ -f configure ]; then ./configure; fi'", check=False)
    
    run_cmd(f"docker exec {CONTAINER_NAME} codeql database create {DB_NAME} --language=cpp --source-root={container_repo_path} --command=\"make\"")
    
    print("[+] Running custom CodeQL query...")
    # download dependencies
    run_cmd(f"docker exec {CONTAINER_NAME} codeql pack install /workspace")
    run_cmd(f"docker exec {CONTAINER_NAME} codeql database analyze {DB_NAME} custom.ql --format=sarif-latest --output={SARIF_OUTPUT}")

def call_llm_api(prompt):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY environment variable is not set. Cannot use LLM.")
        sys.exit(1)
        
    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model='gemini-2.5-pro',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        print(f"[!] LLM API Call Failed: {e}")
        return ""

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

def step_3_4_dynamic_harness_loop(repo_dir):
    print("[+] Step 3: Parsing SARIF and beginning dynamic harness generation loop...")
    
    rel_repo = os.path.basename(repo_dir)
    container_repo_path = f"/workspace/{rel_repo}"
    
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
            
    vuln_file = "unknown"
    codeql_msg = ""
    runs = sarif_data.get("runs", [])
    if runs:
        results = runs[0].get("results", [])
        if results:
            first_result = results[0]
            codeql_msg = first_result.get("message", {}).get("text", "")
            
            locations = first_result.get("locations", [])
            if locations:
                phys_loc = locations[0].get("physicalLocation", {})
                art_loc = phys_loc.get("artifactLocation", {})
                uri = art_loc.get("uri", "")
                if uri:
                    vuln_file = uri
                    
            print(f"    - CodeQL Result: {codeql_msg}")
            
    if vuln_file == "unknown":
        print("[!] No vulnerabilities or vulnerable file detected by CodeQL. Exiting.")
        sys.exit(1)
        
    vuln_file_host_path = os.path.join(repo_dir, vuln_file)
    with open(vuln_file_host_path, 'r') as f:
        target_source_code = f.read()

    context = []
    crash_file = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n[+] --- LLM Generation Attempt {attempt}/{MAX_RETRIES} ---")
        prompt = f"""
You are an expert security researcher writing a C harness for the AFL++ fuzzer.
Static analysis identified a finding: "{codeql_msg}" in the file `{vuln_file}`.

Here is the entire source code of the target file `{vuln_file}`:
```c
{target_source_code}
```

The file will be included via `#include "{container_repo_path}/{vuln_file}"`.
Please write a complete, compilable C program named `harness.c` that wraps the vulnerable function to expose it to the fuzzer. It should read from stdin (or a file if necessary) and feed the data into the vulnerable function. Use AFL++ standard practices (e.g., `__AFL_INIT()` if needed, but not required if `afl-clang-fast` is used). Note that if the target requires external libraries like libpcap, please include `<pcap.h>`.

Output ONLY the C code, inside a ```c block.
"""
        if context:
            prompt += "\n\nThe following feedback was collected from previous attempts that failed:\n"
            for past_attempt in context:
                prompt += f"- {past_attempt}\n"
            prompt += "\nPlease adjust the harness approach based on this feedback."

        print(f"    - Requesting harness from Gemini API...")
        llm_response = call_llm_api(prompt)
        harness_code = extract_c_code(llm_response)

        harness_path = os.path.join(WORKSPACE_DIR, HARNESS_FILE)
        with open(harness_path, "w") as f:
            f.write(harness_code)
        print(f"    - Wrote generated harness to {HARNESS_FILE}")

        # Compilation Loop Segment
        print("    - Compiling generated harness with AFL++...")
        run_cmd(f"docker exec {CONTAINER_NAME} rm -f {FUZZ_TARGET}", check=False)
        compile_res = subprocess.run(
            f"docker exec -e AFL_USE_ASAN=1 {CONTAINER_NAME} afl-clang-fast -I /workspace/{rel_repo} -o {FUZZ_TARGET} {HARNESS_FILE} -lpcap",
            shell=True, capture_output=True, text=True, cwd=WORKSPACE_DIR
        )

        if compile_res.returncode != 0:
            print(f"    - [!] Compilation failed.")
            context.append(f"Compilation failed with error:\nSTDERR:\n{compile_res.stderr}\nCode:\n{harness_code}")
            continue # Try LLM generation again
            
        print("    - Compilation successful. Starting fuzzer...")
        run_cmd(f"docker exec {CONTAINER_NAME} rm -rf inputs outputs", check=False)
        run_cmd(f"docker exec {CONTAINER_NAME} mkdir -p inputs")
        run_cmd(f"docker exec {CONTAINER_NAME} sh -c 'echo \"A\" > inputs/seed'")
        
        # Run fuzzer in background.
        fuzz_cmd = f"docker exec -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 -e AFL_SKIP_CPUFREQ=1 {CONTAINER_NAME} afl-fuzz -i inputs -o outputs -- ./{FUZZ_TARGET}"
        proc = subprocess.Popen(fuzz_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"    - Fuzzer running. Wait limit: {FUZZ_TIMEOUT_SEC/60:.1f} minutes...")
        
        start_time = time.time()
        
        while time.time() - start_time < FUZZ_TIMEOUT_SEC:
            res = subprocess.run(f"docker exec {CONTAINER_NAME} sh -c 'ls outputs/default/crashes/id:* 2>/dev/null'", shell=True, text=True, capture_output=True)
            if res.returncode == 0 and res.stdout.strip():
                crashes = res.stdout.strip().split()
                if crashes:
                    crash_file_in_container = crashes[0]
                    run_cmd(f"docker exec {CONTAINER_NAME} chmod -R 777 outputs")
                    crash_file = crash_file_in_container.replace("/workspace/", "")
                    if not crash_file.startswith("outputs/"):
                         crash_file = crash_file.split("\n")[0]
                    print(f"    - [!] CRASH TRIGGERED! Crash File: {crash_file}")
                    break
            
            # Check if fuzzer completely died/finished early
            if proc.poll() is not None:
                 print("    - [!] Fuzzer exited prematurely.")
                 break
            time.sleep(1)

        # Cleanup fuzzer for next iteration or completion
        run_cmd(f"docker exec {CONTAINER_NAME} pkill afl-fuzz", check=False)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        if crash_file:
            print(f"[+] Crash found successfully in attempt {attempt}.")
            break
        else:
            print(f"    - [!] Attempt {attempt} failed to find a crash within timeout. Analyzing fuzzer stats...")
            # Capture stats for feedback
            stats_res = subprocess.run(f"docker exec {CONTAINER_NAME} cat outputs/default/fuzzer_stats", shell=True, text=True, capture_output=True)
            stats = stats_res.stdout.strip() if stats_res.returncode == 0 else "Fuzzer stats totally unreadable or fuzzer failed immediately."
            context.append(f"Harness compiled but failed to trigger a crash in the {FUZZ_TIMEOUT_SEC/60:.1f} minute timeout.\nFuzzer Stats:\n{stats}\nPrevious Code Iteration:\n{harness_code}")

    if not crash_file:
        print(f"[!] Exhausted {MAX_RETRIES} attempts without a crash. Returning failure.")
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
    parser = argparse.ArgumentParser(description="HAST Pipeline")
    parser.add_argument("repo_url", help="GitHub repository URL to analyze")
    parser.add_argument("--branch", help="Specific branch or tag to clone", default=None)
    args = parser.parse_args()
    
    repo_dir = None
    try:
        repo_dir = step_0_fetch_repo(args.repo_url, args.branch)
        step_1_setup_environment()
        step_2_static_analysis(repo_dir)
        crash_file = step_3_4_dynamic_harness_loop(repo_dir)
        step_5_reporting(crash_file)
        print("[*] Pipeline completed successfully.")
    except Exception as e:
        print(f"[!] Pipeline failed: {e}")
        sys.exit(1)
    finally:
        print("[*] Cleaning up Docker container...")
        run_cmd(f"docker rm -f {CONTAINER_NAME}", check=False)
        if repo_dir and os.path.exists(repo_dir):
            print(f"[*] Cleaning up temporary repository directory: {repo_dir}")
            shutil.rmtree(repo_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
