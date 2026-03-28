from backend.tasks import build_dynamic_fuzzing_env
import os

os.environ["GEMINI_API_KEY"] = os.environ.get("GEMINI_API_KEY", "")
print("Running build_dynamic_fuzzing_env explicitly...")
res = build_dynamic_fuzzing_env("https://github.com/kermitt2/xpdf-3.04.git", "test_task")
print("RESULT:", res)
