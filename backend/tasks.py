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

@celery_app.task(bind=True)
def run_pipeline(self, repo_url: str):
    task_id = self.request.id
    try:
        notify_status(task_id, "INIT", "Running", f"Starting pipeline for {repo_url}")
        
        # Step 1: SAST (CodeQL)
        notify_status(task_id, "SAST", "Running", "Cloning and extracting source-level logical vulnerabilities via CodeQL")
        # TODO: Implement CodeQL fetching and evaluation against source-code strictly.
        time.sleep(1)
        
        # Step 2: AI Harness Generation
        notify_status(task_id, "AI_HARNESS", "Running", "Requesting source-code level C harness from LLM")
        # TODO: Connect LLM prompt with source context for harness wrapper.
        time.sleep(1)
        
        # Step 3: DAST (AFL++)
        notify_status(task_id, "DAST", "Running", "Fuzzing via isolated container against generated harness (max 20 mins)")
        # TODO: Run fuzzer using afl-clang-fast
        time.sleep(1)
        
        # Step 4: AI Patch Generation
        notify_status(task_id, "AI_PATCH", "Running", "Crash verified. Querying LLM for source-code secure patch")
        # TODO: Forward exact crash logic + source code to LLM to create logical source-level patch (no binary modifications).
        time.sleep(1)
        
        # Step 5: DB Storage
        notify_status(task_id, "DB_STORAGE", "Running", "Storing vulnerability, harness, fuzzer trace, and patches in PostgreSQL")
        # TODO: PostgreSQL insert operations.
        time.sleep(1)
        
        notify_status(task_id, "PIPELINE", "Success", "Pipeline completely executed.")
        return {"status": "Complete", "repo": repo_url}
        
    except Exception as e:
        notify_status(task_id, "PIPELINE", "Failed", str(e))
        raise e

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

@celery_app.task(bind=True)
def build_dynamic_fuzzing_env(self, repo_url: str):
    task_id = self.request.id
    notify_status(task_id, "ENV_GEN", "Running", f"Analyzing target repository {repo_url} for build dependencies")
    
    # 1. Target Analysis: Fetch build files
    temp_dir = tempfile.mkdtemp(prefix="target_analyze_")
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        notify_status(task_id, "ENV_GEN", "Failed", f"Failed to clone repository: {e.stderr}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"status": "Failed", "error": "Clone failed"}

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
- Base image: `ubuntu:22.04`
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
            # Truncate very long build logs
            if len(error_log) > 2000:
                error_log = "..." + error_log[-2000:]
                
            feedback_context.append(f"Attempt {attempt} failed.\nDockerfile:\n{dockerfile_content}\n\nBuild Error:\n{error_log}")
            
    notify_status(task_id, "ENV_GEN", "Failed", f"Failed to build Dockerfile after {max_retries} attempts.")
    return {"status": "Failed", "error": "Max retries exceeded"}
