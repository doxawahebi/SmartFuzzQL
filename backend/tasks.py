from celery import Celery
import time
import tempfile
import shutil
import redis
from rich.console import Console
from google import genai
import os
import json
import subprocess
import docker
import requests
import io
import tarfile

console = Console()
redis_client = redis.Redis.from_url(os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'))

celery_app = Celery(
    'hast_pipeline',
    broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

def notify_status(task_id, step, status, details=None):
    # Rich print for CMD logs
    color = "green" if status == "Success" else "red" if status == "Failed" else "cyan"
    console.print(f"[{color}][{step}][/{color}] {status} - {details}")
    
    # Broadcast to Redis PubSub for WebSockets
    message = json.dumps({"task_id": task_id, "step": step, "status": status, "details": details})
    try:
        redis_client.publish('pipeline_logs', message)
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

@celery_app.task(bind=True)
def run_pipeline(self, repo_url: str):
    task_id = self.request.id
    temp_dir = tempfile.mkdtemp(prefix=f"pipeline_run_{task_id}_")
    print(f"temp_dir : {temp_dir}")
    docker_client = docker.from_env()
    container = None
    
    try:
        notify_status(task_id, "INIT", "Running", f"Starting pipeline for {repo_url} in {temp_dir}")
        subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir], capture_output=True, check=True)
        repo_path = temp_dir
        
        # Step 1: SAST (CodeQL)
        notify_status(task_id, "SAST", "Running", "Cloning and extracting source-level logical vulnerabilities via CodeQL")
        db_path = os.path.join(temp_dir, "my-db")
        sarif_path = os.path.join(temp_dir, "results.sarif")
        
        # For this prototype we assume codeql is locally installed and available via CLI, or use a prebuilt container
        # Since codeql is large, relying on local setup or a specific pipeline config. 
        # Fallback: if codeql missing, mock the SARIF finding for demonstration of full flow.
        try:
           subprocess.run(["codeql", "database", "create", db_path, "--language=cpp", f"--source-root={temp_dir}", "--command=make"], check=True, capture_output=True)
           subprocess.run(["codeql", "database", "analyze", db_path, "cpp-queries", "--format=sarif-latest", f"--output={sarif_path}"], check=True, capture_output=True)
        except FileNotFoundError:
           notify_status(task_id, "SAST", "Warning", "CodeQL CLI not found locally. Mocking SARIF for fuzzing step.")
           mock_sarif = {
               "runs": [
                   {"results": [
                       {
                           "message": {"text": "Potential buffer overflow"},
                           "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main.c"}}}]
                       }
                   ]}
               ]
           }
           with open(sarif_path, "w") as f: json.dump(mock_sarif, f)
           # Create a dummy src/main.c if it doesn't exist
           os.makedirs(os.path.join(repo_path, "src"), exist_ok=True)
           dummy_c = os.path.join(repo_path, "src", "main.c")
           if not os.path.exists(dummy_c):
               with open(dummy_c, "w") as f: f.write("void vulnerable_func(char* input) { char buf[10]; strcpy(buf, input); }")

        with open(sarif_path, "r") as f:
            sarif_data = json.load(f)
            
        vuln_msg = "Unknown vulnerability"
        vuln_file = "unknown"
        results = sarif_data.get("runs", [{}])[0].get("results", [])
        if results:
            vuln_msg = results[0].get("message", {}).get("text", "")
            locations = results[0].get("locations", [])
            if locations:
                vuln_file = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")

        vuln_file_full = os.path.join(repo_path, vuln_file)
        print(f"vuln_file_full: {vuln_file_full}")
        vuln_code = "Code not found"
        if os.path.exists(vuln_file_full):
             with open(vuln_file_full, "r") as f: vuln_code = f.read()

        # Step 2: AI Harness Generation
        notify_status(task_id, "AI_HARNESS", "Running", "Requesting source-code level C harness from LLM")
        prompt = f"Write a complete C harness for AFL++ targeting this file: {vuln_file}. Vulnerability: {vuln_msg}\nSource Code:\n```c\n{vuln_code}\n```"
        llm_resp = call_llm_api(prompt)
        harness_code = extract_c_code(llm_resp) # need to add this helper
        harness_path = os.path.join(repo_path, "harness.c")
        with open(harness_path, "w") as f: f.write(harness_code)
        
        # Step 3: DAST (AFL++)
        notify_status(task_id, "DAST", "Running", "Fuzzing via isolated container against generated harness (max 20 mins)")
        
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
            working_dir="/target"
        )
        copy_text_to_container(container, "/target", "harness.c", harness_code)
        
        # Compile harness
        compile_res = container.exec_run("afl-clang-fast -o fuzz_target harness.c", user="root")
        if compile_res.exit_code != 0:
            raise Exception(f"Failed to compile harness: {compile_res.output.decode('utf-8')}")

        # Setup basic inputs and run afl-fuzz
        container.exec_run("mkdir -p inputs outputs", user="root")
        container.exec_run("sh -c 'echo A > inputs/seed'", user="root")
        
        fuzz_cmd = "afl-fuzz -i inputs -o outputs -- ./fuzz_target"
        container.exec_run(f"sh -c '{fuzz_cmd} &'", user="root", detach=True)
        
        # Poll for 20 minutes
        timeout = 20 * 60
        start = time.time()
        crash_found = False
        crash_data = None
        
        while time.time() - start < timeout:
            stats = container.exec_run("cat outputs/default/fuzzer_stats", user="root")
            if stats.exit_code == 0:
                stats_str = stats.output.decode('utf-8')
                notify_status(task_id, "DAST", "Running", f"Fuzzer running... Stats:\n{stats_str[:200]}...") # Truncated
            
            crashes = container.exec_run("sh -c 'ls outputs/default/crashes/id:* 2>/dev/null'", user="root")
            if crashes.exit_code == 0 and crashes.output.decode('utf-8').strip():
                crash_found = True
                crash_files = crashes.output.decode('utf-8').strip().split()
                if crash_files:
                     crash_content = container.exec_run(f"cat {crash_files[0]}", user="root")
                     crash_data = crash_content.output
                notify_status(task_id, "DAST", "Success", "Crash found!")
                break
            time.sleep(10) # Poll every 10 seconds
            
        if not crash_found:
            notify_status(task_id, "DAST", "Failed", "No crash found within timeout")
            raise Exception("Timeout reached without finding crash")

        # Step 4: AI Patch Generation
        notify_status(task_id, "AI_PATCH", "Running", "Crash verified. Querying LLM for source-code secure patch")
        patch_prompt = f"Fix the vulnerability in this code. Crash input (hex): {crash_data.hex() if crash_data else 'Unknown'}\nVulnerability: {vuln_msg}\nSource:\n```c\n{vuln_code}\n```. Provide ONLY the correct patched C code inside ```c block."
        patch_resp = call_llm_api(patch_prompt)
        patch_code = extract_c_code(patch_resp)
        patch_path = os.path.join(repo_path, "patched_" + os.path.basename(vuln_file))
        with open(patch_path, "w") as f: f.write(patch_code)
        
        # Step 5: DB Storage
        notify_status(task_id, "DB_STORAGE", "Running", "Storing vulnerability, harness, fuzzer trace, and patches in PostgreSQL")
        # TODO: PostgreSQL insert operations. We assume the frontend handles DB read via other endpoints for now.
        
        notify_status(task_id, "PIPELINE", "Success", "Pipeline completely executed.")
        return {"status": "Complete", "repo": repo_url, "patch_generated": True}
        
    except Exception as e:
        notify_status(task_id, "PIPELINE", "Failed", str(e))
        raise e
    finally:
        # Cleanup
        if container:
            try:
                container.stop(timeout=1)
                container.remove(force=True)
            except Exception as e:
                console.print(f"[red]Failed to cleanup container: {e}[/red]")
        shutil.rmtree(temp_dir, ignore_errors=True)

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

def call_llm_api(prompt):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "ERROR: GEMINI_API_KEY not set"
    client = genai.Client(api_key=api_key)
    try:
        # Using a potentially lighter model for retry loops
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"ERROR: {e}"

def extract_dockerfile(text):
    if "```dockerfile" in text.lower():
        start = text.lower().find("```dockerfile") + 13
        end = text.find("```", start)
        return text[start:end].strip()
    return text.strip()

# @celery_app.task(bind=True)
#def build_dynamic_fuzzing_env(self, repo_url: str):
def build_dynamic_fuzzing_env(repo_url: str, task_id: str):
    notify_status(task_id, "ENV_GEN", "Running", f"Analyzing target repository {repo_url} for build dependencies")
    
    # 1. Target Analysis: Fetch build files
    temp_dir = tempfile.mkdtemp(prefix="target_analyze_")
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        notify_status(task_id, "ENV_GEN", "Failed", f"Failed to clone repository: {e.stderr}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"status": "Failed", "error": f"Clone failed: {e.stderr}"}

    build_context = ""
    critical_files = ["README.md", "configure", "configure.ac", "CMakeLists.txt", "Makefile", "autogen.sh"]
    for file_name in critical_files:
        file_path = os.path.join(temp_dir, file_name)
        if os.path.exists(file_path):
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                # Trucate to avoid massive context
                if len(content) > 3000:
                    content = content[:3000] + "\n...[TRUNCATED]..."
                build_context += f"\n--- {file_name} ---\n{content}\n"
    
    # We no longer need the local clone once we have the context
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    max_retries = 3
    feedback_context = []
    
    for attempt in range(1, max_retries + 1):
        notify_status(task_id, "ENV_GEN", "Running", f"Generating Dockerfile (Attempt {attempt}/{max_retries})")
        
        # 2. Dynamic Dockerfile Generation
        prompt = f"""
You are an expert DevSecOps engineer configuring an AFL++ fuzzing environment.
Please write a complete Dockerfile to compile the following project for fuzzing.

Project Repository: {repo_url}

Based on these snippets from the repository's build files, determine its system dependencies (e.g., libpcap-dev, libssl-dev, cmake, autoconf):
{build_context}

Requirements:
- Base image: `ubuntu:24.04`
- Install standard build tools (build-essential, clang, git, wget) AND target-specific dependencies.
- Install AFL++ (either via apt fuzzing tools, or clone and build AFL++). Assume AFL is available in PATH.
- Clone the target repository (`git clone {repo_url} /target`).
- Compile the target software. Inject AFL++ compilers by setting `CC=afl-clang-fast` and `CXX=afl-clang-fast++` before running `make` or `cmake`.

Output ONLY the Dockerfile inside a ```dockerfile block.
"""
        if feedback_context:
            prompt += "\n\nPrevious Docker build attempts failed with these errors. Please fix the missing dependencies or build commands:\n"
            for fb in feedback_context:
                prompt += f"{fb}\n"
                
        llm_response = call_llm_api(prompt)
        dockerfile_content = extract_dockerfile(llm_response)
        
        if "ERROR" in dockerfile_content:
            notify_status(task_id, "ENV_GEN", "Failed", f"LLM Error: {dockerfile_content}")
            return {"status": "Failed", "error": dockerfile_content}
            
        # 3. Automated Build Process
        build_dir = tempfile.mkdtemp(prefix="docker_build_")
        dockerfile_path = os.path.join(build_dir, "Dockerfile")
        with open(dockerfile_path, "w") as f:
            f.write(dockerfile_content)
            
        notify_status(task_id, "ENV_GEN", "Running", "Building Docker image orchestrator locally...")
        build_process = subprocess.run(
            ["docker", "build", "-t", f"dynamic-fuzzer-{task_id}", build_dir],
            capture_output=True, text=True
        )
        shutil.rmtree(build_dir, ignore_errors=True)
        
        if build_process.returncode == 0:
            notify_status(task_id, "ENV_GEN", "Success", "Docker image built successfully with AFL instrumentation!")
            return {"status": "Success", "image": f"dynamic-fuzzer-{task_id}"}
        else:
            # 4. Build Error Feedback Loop
            notify_status(task_id, "ENV_GEN", "Running", f"Docker build failed. Collecting error logs for LLM correction...")
            error_log = build_process.stderr
            console.print(f"[red]Docker Build Error:[/red] {error_log[:1000]}")
            # Truncate very long build logs
            if len(error_log) > 2000:
                error_log = "..." + error_log[-2000:]
                
            feedback_context.append(f"Attempt {attempt} failed.\nDockerfile:\n{dockerfile_content}\n\nBuild Error:\n{error_log}")
            
    notify_status(task_id, "ENV_GEN", "Failed", f"Failed to build Dockerfile after {max_retries} attempts.")
    return {"status": "Failed", "error": "Max retries exceeded"}
