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
