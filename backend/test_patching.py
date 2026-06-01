"""Unit tests for the shared Auto-Remediation helpers in patching.py."""

import patching

SAMPLE = """/* license header with { braces } in a comment */
#include <stdio.h>

static const char *names[] = { "a", "b" };

void helper(int x) {
    if (x) { printf("%d", x); }
}

void bootp_print(const u_char *bp, u_int length)
{
    u_int flags;
    if (length < 4)
        return;
    /* missing bound check */
    flags = EXTRACT_16BITS(&bp->bp_flags);
    if (flags & 0x8000) {
        printf("broadcast");
    }
}

int main(void) { return 0; }
"""

VULN_LINE = SAMPLE.split("\n").index("    flags = EXTRACT_16BITS(&bp->bp_flags);") + 1


def test_find_enclosing_function_isolates_the_right_function():
    start, end = patching.find_enclosing_function(SAMPLE, VULN_LINE)
    snippet = "\n".join(SAMPLE.split("\n")[start : end + 1])
    assert "bootp_print" in snippet
    # Neighbours and the brace-containing array literal must not leak in.
    assert "helper" not in snippet
    assert "names[]" not in snippet
    assert "int main" not in snippet


def test_extract_vulnerable_function_includes_signature_and_body():
    fn = patching.extract_vulnerable_function(SAMPLE, VULN_LINE)
    assert fn.startswith("void bootp_print(")
    assert fn.rstrip().endswith("}")
    assert "EXTRACT_16BITS" in fn


def test_splice_patch_replaces_only_the_function():
    patched_fn = (
        "void bootp_print(const u_char *bp, u_int length)\n"
        "{\n    if (length < 4) return;\n    ND_TCHECK2(bp->bp_flags, 2);\n}"
    )
    result = patching.splice_patch(SAMPLE, VULN_LINE, patched_fn)
    assert "ND_TCHECK2" in result
    # Untouched neighbours survive; the old vulnerable read is gone.
    assert "void helper(int x)" in result
    assert "int main(void)" in result
    assert "EXTRACT_16BITS" not in result


def test_extraction_returns_none_for_out_of_range_line():
    assert patching.find_enclosing_function(SAMPLE, 9999) is None
    assert patching.extract_vulnerable_function("only one line", 5) is None


def test_splice_falls_back_to_patch_when_no_function_found():
    # No line / unfindable function -> return the patch verbatim (no splice).
    assert patching.splice_patch("x", None, "PATCH") == "PATCH"


def test_extract_c_code_prefers_c_fence():
    assert patching.extract_c_code("blah\n```c\nint x;\n```\ntail") == "int x;"
    assert patching.extract_c_code("```\nint y;\n```") == "int y;"
    assert patching.extract_c_code("no fence here").strip() == "no fence here"


def test_build_patch_prompt_embeds_inputs():
    prompt = patching.build_patch_prompt("int f(){}", "buffer overflow", "deadbeef")
    assert "int f(){}" in prompt
    assert "buffer overflow" in prompt
    assert "deadbeef" in prompt
    assert "Patch ONLY the function below" in prompt
