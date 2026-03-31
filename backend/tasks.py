from celery import Celery
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
    console.print(f"[{color}][{step}][/{color}] {status} - {escape(str(details or ''))}")
    
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
    console.print(f"temp_dir : {temp_dir}")
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
        custom_ql = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom.ql")
        def run_codeql_streaming(cmd):
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    notify_status(task_id, "SAST", "Running", line)
            proc.wait()
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, cmd)
        try:
           run_codeql_streaming(["codeql", "database", "create", db_path, "--language=cpp", f"--source-root={temp_dir}", "--build-mode=none"])
           run_codeql_streaming(["codeql", "database", "analyze", db_path, custom_ql, "--search-path=/opt/codeql/qlpacks", "--format=sarif-latest", f"--output={sarif_path}"])
        except FileNotFoundError:
           notify_status(task_id, "SAST", "Warning", "CodeQL CLI not found. Mocking SARIF for fuzzing step.")
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
        llm_resp = call_llm_api(prompt, model='gemini-2.5-flash', task_type='harness')
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
        
        # Compile harness with feedback loop
        compile_cmd = "afl-clang-fast -I/usr/local/include/afl++ -o fuzz_target harness.c"
        max_compile_retries = 3
        compile_success = False

        for attempt in range(1, max_compile_retries + 1):
            notify_status(task_id, "DAST", "Running", f"Compiling harness (Attempt {attempt}/{max_compile_retries})...")
            compile_res = container.exec_run(compile_cmd, user="root", demux=True)

            if compile_res.exit_code == 0:
                compile_success = True
                notify_status(task_id, "DAST", "Success", "Harness compiled successfully.")
                break

            # When demux=True is set, compile_res.output returns a (stdout_bytes, stderr_bytes) tuple.
            stdout_bytes, stderr_bytes  ='replace'
            stdout_str = stdout_bytes.decode('utf-8', errors='replace').strip() if stdout_bytes else "No STDOUT"
            stderr_str = stderr_bytes.decode('utf-8', errors='replace').strip() if stderr_bytes else "No STDERR"
            
            # Detailed error message formatting for better debugging of compilation issues
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
            else:
                notify_status(task_id, "DAST", "Warning", f"Compilation failed. Requesting quick fix from LLM...")
                fix_prompt = f"The following C harness failed to compile. Fix the errors based on the compiler output and return only the corrected complete C code. Do not explain.\n\nCompiler Output:\n{stderr_str}\n\nBroken Harness:\n```c\n{harness_code}\n```"
                fix_resp = call_llm_api(fix_prompt, model='gemini-2.5-flash', task_type='harness')
                harness_code = extract_c_code(fix_resp)
                
                # Update the local file and container
                with open(harness_path, "w") as f: f.write(harness_code)
                copy_text_to_container(container, "/target", "harness.c", harness_code)

        if not compile_success:
            raise Exception("Failed to compile harness after maximum retries.")

        TIME_MINITUTE = 1
        POLL_INTERVAL = 10

        # Setup basic inputs and run afl-fuzz
        container.exec_run("mkdir -p inputs outputs", user="root")
        container.exec_run("sh -c 'echo A > inputs/seed'", user="root")
        
        notify_status(task_id, "DAST", "Running", f"Starting AFL++ fuzzing... This may take up to {TIME_MINITUTE} minutes. Monitoring for crashes.")
        fuzz_cmd = "afl-fuzz -i ./inputs -o ./outputs -m none -- ./fuzz_target > fuzzer_stdout.log 2> fuzzer_stderr.log"
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
        patch_resp = call_llm_api(patch_prompt, model='gemini-2.5-flash', task_type='patch')
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

def call_llm_api(prompt, model='gemini-2.5-flash', task_type=None):
    if os.environ.get("DEBUG_BYPASS_LLM", "False").lower() in ("true", "1", "yes"):
        debug_assets_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug_assets")
        
        if task_type == "harness" or "Write a complete C harness" in prompt or "Fix the errors based on the compiler output" in prompt:
            mock_file = os.path.join(debug_assets_dir, "mock_harness.c")
            if not os.path.exists(mock_file):
                console.print(f"[red][DEBUG] {mock_file} not found[/red]")
                raise Exception(f"[DEBUG] {mock_file} not found")
            with open(mock_file, "r") as f:
                return f.read()

        elif task_type == "patch" or "Fix the vulnerability in this code" in prompt:
            mock_file = os.path.join(debug_assets_dir, "mock_patch.c")
            if not os.path.exists(mock_file):
                console.print(f"[red][DEBUG] {mock_file} not found[/red]")
                raise Exception(f"[DEBUG] {mock_file} not found")
            with open(mock_file, "r") as f:
                return f.read()
                
        elif task_type == "docker_deps" or "configuring an AFL++ fuzzing environment" in prompt:
            mock_file = os.path.join(debug_assets_dir, "mock_deps.txt")
            if os.path.exists(mock_file):
                with open(mock_file, "r") as f:
                    return f.read()
            return "pkg-config libssl-dev zlib1g-dev"

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "ERROR: GEMINI_API_KEY not set"
    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model=model,
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

#def build_dynamic_fuzzing_env(repo_url: str, task_id: str):
@celery_app.task(bind=True)
def build_dynamic_fuzzing_env(self, repo_url: str, task_id: str):
    notify_status(task_id, "ENV_GEN", "Running", f"Analyzing target repository {repo_url} for build dependencies")
    
    # 1. Target Analysis & Build Context Setup
    build_dir = tempfile.mkdtemp(prefix="docker_build_")
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, build_dir], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        notify_status(task_id, "ENV_GEN", "Failed", f"Failed to clone repository: {e.stderr}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"status": "Failed", "error": f"Clone failed: {e.stderr}"}

    build_context = ""
    critical_files = ["README.md", "configure", "configure.ac", "CMakeLists.txt", "Makefile", "autogen.sh"]
    for file_name in critical_files:
        file_path = os.path.join(build_dir, file_name)
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
    
    # Locate templates in the backend directory
    # TODO : save dynamic-fuzzer.Dockerfile in DB.
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(backend_dir, "Dockerfile.template")
    workspace_dockerfile_path = os.path.join(os.path.dirname(backend_dir), "dynamic-fuzzer.Dockerfile")

    try:
        with open(template_path, "r") as f:
            template_content = f.read()
    except FileNotFoundError:
        notify_status(task_id, "ENV_GEN", "Failed", "Dockerfile.template not found.")
        shutil.rmtree(build_dir, ignore_errors=True)
        return {"status": "Failed", "error": "Dockerfile.template missing"}
    
    for attempt in range(1, max_retries + 1):
        notify_status(task_id, "ENV_GEN", "Running", f"Generating dependencies via LLM (Attempt {attempt}/{max_retries})")
        
        # 2. Dependency Resolution via LLM
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
            prompt += "\n\nPrevious Docker build attempts failed with these errors. Please fix the missing dependencies or build commands:\n"
            for fb in feedback_context:
                prompt += f"{fb}\n"
                
        llm_response = call_llm_api(prompt, task_type='docker_deps')
        
        # Clean the response to ensure only space-separated packages are present
        target_deps = llm_response.replace("```dockerfile", "").replace("```", "").replace("\n", " ").strip()
        
        if "ERROR" in target_deps:
            notify_status(task_id, "ENV_GEN", "Failed", f"LLM Error: {target_deps}")
            shutil.rmtree(build_dir, ignore_errors=True)
            return {"status": "Failed", "error": target_deps}
            
        # 3. Dockerfile Injection
        dockerfile_content = template_content.replace("{{ TARGET_DEPS }}", target_deps)
        
        # Save to Workspace Dockerfile explicitly for user review if needed
        with open(workspace_dockerfile_path, "w") as f:
            f.write(dockerfile_content)
            
        notify_status(task_id, "ENV_GEN", "Running", f"Building Docker orchestrator locally... Injecting: {target_deps}")
        build_process = subprocess.run(
            ["docker", "build", "-f", workspace_dockerfile_path, "-t", f"dynamic-fuzzer-{task_id}", build_dir],
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
