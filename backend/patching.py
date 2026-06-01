"""Auto-Remediation helpers shared by the Celery backend (`tasks.py`) and the standalone
CLI (`pipeline.py`).

This module is the single source of truth for the patch prompt and for the *function-scoped*
diff that the dashboard renders. Instead of feeding the LLM the first few KB of a large file
(which, for targets like tcpdump's `print-bootp.c`, never contains the vulnerable function),
we extract the enclosing function around the SAST sink line, ask the LLM to patch *that*
function, then splice the patched function back into the original file. The result is a clean,
aligned `original` vs `patched` diff whose line numbers still match the SARIF graph so the
ReportViewer "click a node -> reveal the line" feature keeps working.

See `docs/auto-remediation.md` for the full feature spec.
"""

# Cap source interpolated into a prompt so a large file can't blow the context window. Only
# used as a fallback when the enclosing function cannot be isolated.
MAX_PROMPT_CHARS = 3000

# Upper bound on how many lines an "enclosing function" may span before we treat the brace
# match as unreliable and fall back to a plain window / whole-file prompt.
MAX_FUNCTION_LINES = 600


def extract_c_code(llm_response: str) -> str:
    """Pull the C source out of an LLM response, preferring a ```c fenced block, then any
    fenced block, then the whole (stripped) text."""
    if not llm_response:
        return ""
    if "```c" in llm_response:
        start = llm_response.find("```c") + 4
        end = llm_response.find("```", start)
        return (
            llm_response[start:end].strip()
            if end != -1
            else llm_response[start:].strip()
        )
    if "```" in llm_response:
        start = llm_response.find("```") + 3
        end = llm_response.find("```", start)
        return (
            llm_response[start:end].strip()
            if end != -1
            else llm_response[start:].strip()
        )
    return llm_response.strip()


def truncate_for_prompt(text: str, max_chars: int = MAX_PROMPT_CHARS) -> str:
    """Cap source code interpolated into an LLM prompt."""
    if text and len(text) > max_chars:
        return text[:max_chars] + "\n...[TRUNCATED]..."
    return text


def find_enclosing_function(
    source: str, line: int, max_lines: int = MAX_FUNCTION_LINES
):
    """Return the ``(start_idx, end_idx)`` 0-based inclusive line range of the C function
    enclosing the 1-based ``line``, or ``None`` if it cannot be isolated.

    Heuristic brace matcher: track top-level brace depth across the file. The function body is
    the depth ``0 -> >0 -> 0`` region that contains ``line``; the signature/leading doc-comment
    above the opening brace is folded in by walking upward over contiguous lines that are not
    obviously the end of the previous statement (``;`` / ``}``) or a preprocessor directive.
    Braces inside strings/comments are not parsed out — acceptable for a best-effort scope hint.
    """
    if not source or line < 1:
        return None
    lines = source.split("\n")
    if line > len(lines):
        return None
    target = line - 1  # 0-based

    depth = 0
    unit_start = 0  # first line of the current top-level unit
    body_open = None  # line where the current function body opened (depth 0 -> >0)
    for i, ln in enumerate(lines):
        prev_depth = depth
        depth += ln.count("{") - ln.count("}")
        if depth < 0:
            depth = 0
        if prev_depth == 0 and depth > 0:
            body_open = i
        elif prev_depth > 0 and depth == 0:
            # A top-level unit just closed at line i.
            if body_open is not None and unit_start <= target <= i:
                start = body_open
                while (
                    start > unit_start
                    and lines[start - 1].strip()
                    and not lines[start - 1].rstrip().endswith((";", "}"))
                    and not lines[start - 1].lstrip().startswith("#")
                ):
                    start -= 1
                if i - start + 1 > max_lines:
                    return None
                return (start, i)
            unit_start = i + 1
            body_open = None
    return None


def extract_vulnerable_function(source: str, line):
    """Return the source text of the C function enclosing ``line`` (1-based), or ``None``."""
    if not line:
        return None
    rng = find_enclosing_function(source, line)
    if rng is None:
        return None
    start, end = rng
    return "\n".join(source.split("\n")[start : end + 1]).strip()


def splice_patch(source: str, line, patched_function: str) -> str:
    """Replace the function enclosing ``line`` (1-based) in ``source`` with
    ``patched_function`` and return the full patched file.

    Falls back to returning ``patched_function`` verbatim when the enclosing function cannot be
    located (e.g. no sink line, or the source was never read)."""
    rng = find_enclosing_function(source, line) if line else None
    if rng is None:
        return patched_function
    start, end = rng
    lines = source.split("\n")
    spliced = lines[:start] + patched_function.split("\n") + lines[end + 1 :]
    return "\n".join(spliced)


def build_patch_prompt(vuln_snippet: str, vuln_msg: str, crash_hex: str) -> str:
    """The shared patch prompt. ``vuln_snippet`` should be the enclosing vulnerable function
    (preferred) or a truncated file. We ask for a drop-in replacement of the *same* function so
    the spliced diff stays minimal and aligned."""
    return (
        "You are fixing a security vulnerability in C code.\n"
        f"Crash input (hex): {crash_hex or 'Unknown'}\n"
        f"Vulnerability: {vuln_msg}\n"
        "Patch ONLY the function below. Keep the same function signature so it is a drop-in "
        "replacement, change as little as possible, and do not add commentary.\n"
        "Vulnerable function:\n"
        f"```c\n{vuln_snippet}\n```\n"
        "Return ONLY the complete patched function inside a single ```c code block."
    )
