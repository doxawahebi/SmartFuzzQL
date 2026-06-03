"""Joern-based SAST fallback.

CodeQL needs a usable build/extraction to find vulnerabilities. When that fails
(the target won't build, or the no-build extraction yields nothing), Joern can
extract an AST/CFG/CPG directly from source — no compilation required — and find
the same vulnerability classes.

To keep the rest of the pipeline untouched, Joern's findings are converted into
the *same SARIF shape CodeQL emits* (see ``joern_raw_to_sarif``). The Joern Scala
script (``joern/extract_vulns.sc``) writes a neutral intermediate JSON; this module
turns that into the vulnerability + call-graph SARIF documents that
``tasks.py``/``pipeline.py`` already know how to parse.

This module is shared by both the Celery backend (``tasks.py``) and the standalone
CLI (``pipeline.py``), mirroring how ``patching.py`` is shared.
"""

import json
import os
import subprocess

# Single source of truth for the dangerous sinks and untrusted input sources.
# ``tasks.py`` imports these so its DANGEROUS_FUNCS / CALL_EDGE_RULE_ID never drift
# from the Joern detection logic, and they are passed to the Joern script as params
# so the Scala side has no hardcoded duplicate either.
DANGEROUS_FUNCS = {"strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"}
INPUT_SOURCE_FUNCS = {"getenv", "fgets", "read", "recv", "fread"}

# Rule IDs mirror the CodeQL query @id values so downstream code (severity mapping,
# call-edge filtering) treats Joern findings identically to CodeQL findings.
TAINT_RULE_ID = "cpp/taint-buffer-overflow"
CALL_EDGE_RULE_ID = "cpp/call-graph-edges"

# Path to the Joern extraction script, relative to this module.
JOERN_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "joern", "extract_vulns.sc"
)
JOERN_RAW_FILENAME = "joern_raw.json"


def _rel_uri(path: str, import_root: str) -> str:
    """Normalize a Joern file path to a repo-relative URI matching CodeQL's SARIF.

    Joern reports paths relative to the import root or as absolute paths; downstream
    code does ``os.path.join(repo_path, uri)``, so the URI must be repo-relative.
    """
    if not path:
        return ""
    path = path.replace("\\", "/")
    root = (import_root or "").replace("\\", "/").rstrip("/")
    if root and path.startswith(root + "/"):
        path = path[len(root) + 1 :]
    return path.lstrip("/")


def _physical_location(file_uri: str, line, start_col=None, end_col=None) -> dict:
    region = {}
    if line is not None:
        region["startLine"] = line
    if start_col is not None:
        region["startColumn"] = start_col
    if end_col is not None:
        region["endColumn"] = end_col
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file_uri},
            "region": region,
        }
    }


def _sarif_doc(rule_id: str, results: list) -> dict:
    """Wrap results in a minimal SARIF document with the runs[0].results shape the
    pipeline reads. Only the fields the parsers touch are populated."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Joern",
                        "rules": [{"id": rule_id}],
                    }
                },
                "results": results,
            }
        ],
    }


def joern_raw_to_sarif(raw: dict, import_root: str) -> tuple[dict, dict]:
    """Convert the Joern script's neutral JSON into (vuln_sarif, callgraph_sarif).

    ``raw`` shape (produced by joern/extract_vulns.sc)::

        {
          "findings": [
            {"message": str,
             "sink": {"file": str, "line": int, "col": int, "endCol": int},
             "flow": [{"code": str, "file": str, "line": int, "col": int, "endCol": int}, ...]}
          ],
          "call_edges": [{"caller": str, "callee": str, "file": str, "line": int}, ...]
        }

    Returns SARIF documents matching CodeQL's output so the existing parsers
    (_select_vulnerability, _select_taint_result/_extract_taint_path,
    _parse_call_edges) consume them unchanged.
    """
    vuln_results = []
    for finding in raw.get("findings", []) or []:
        sink = finding.get("sink", {}) or {}
        sink_uri = _rel_uri(sink.get("file", ""), import_root)
        location = _physical_location(
            sink_uri,
            sink.get("line"),
            sink.get("col"),
            sink.get("endCol"),
        )

        thread_flow_locations = []
        for step in finding.get("flow", []) or []:
            step_uri = _rel_uri(step.get("file", ""), import_root)
            thread_flow_locations.append(
                {
                    "location": {
                        "message": {"text": step.get("code", "")},
                        **_physical_location(
                            step_uri,
                            step.get("line"),
                            step.get("col"),
                            step.get("endCol"),
                        ),
                    }
                }
            )

        result = {
            "ruleId": TAINT_RULE_ID,
            "level": "error",
            "message": {
                "text": finding.get("message")
                or "Unsafe buffer write: tainted value reaches a dangerous C string function."
            },
            "locations": [location],
        }
        if thread_flow_locations:
            result["codeFlows"] = [
                {"threadFlows": [{"locations": thread_flow_locations}]}
            ]
        vuln_results.append(result)

    call_edge_results = []
    for edge in raw.get("call_edges", []) or []:
        caller = (edge.get("caller") or "").strip()
        callee = (edge.get("callee") or "").strip()
        if not caller or not callee:
            continue
        edge_uri = _rel_uri(edge.get("file", ""), import_root)
        call_edge_results.append(
            {
                "ruleId": CALL_EDGE_RULE_ID,
                "message": {"text": f"CALL_EDGE {caller} -> {callee}"},
                "locations": [_physical_location(edge_uri, edge.get("line"))],
            }
        )

    return _sarif_doc(TAINT_RULE_ID, vuln_results), _sarif_doc(
        CALL_EDGE_RULE_ID, call_edge_results
    )


def build_joern_command(
    repo_dir: str, out_dir: str, script: str = JOERN_SCRIPT
) -> list:
    """Construct the ``joern --script`` argv that runs the extraction on ``repo_dir``
    and writes ``joern_raw.json`` into ``out_dir``. Shared so the CLI can mirror the
    same params when it invokes Joern inside its container."""
    return [
        "joern",
        "--script",
        script,
        "--param",
        f"inDir={repo_dir}",
        "--param",
        f"outDir={out_dir}",
        "--param",
        f"sinks={','.join(sorted(DANGEROUS_FUNCS))}",
        "--param",
        f"sources={','.join(sorted(INPUT_SOURCE_FUNCS))}",
    ]


def run_joern_analysis(
    task_id, repo_dir, sarif_path, callgraph_sarif_path, out_dir=None, notify=None
):
    """Run Joern on ``repo_dir`` and write CodeQL-shaped SARIF to ``sarif_path`` and
    ``callgraph_sarif_path``. Raises if Joern is missing or the script fails, so the
    caller can decide how to proceed.

    ``notify`` is an optional ``callable(line: str)`` for streaming progress (the
    backend passes a lambda that calls ``notify_status(..., "SAST", "Running", line)``).
    """
    out_dir = out_dir or os.path.dirname(os.path.abspath(sarif_path)) or "."
    raw_path = os.path.join(out_dir, JOERN_RAW_FILENAME)
    if os.path.exists(raw_path):
        os.remove(raw_path)

    cmd = build_joern_command(repo_dir, out_dir)
    if notify:
        notify(f"Running Joern: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for line in proc.stdout:
        line = line.rstrip()
        if line and notify:
            notify(line)
    proc.wait()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    if not os.path.exists(raw_path):
        raise FileNotFoundError(
            f"Joern finished but produced no {JOERN_RAW_FILENAME} at {raw_path}"
        )

    with open(raw_path, "r") as f:
        raw = json.load(f)

    vuln_sarif, callgraph_sarif = joern_raw_to_sarif(raw, import_root=repo_dir)
    with open(sarif_path, "w") as f:
        json.dump(vuln_sarif, f)
    with open(callgraph_sarif_path, "w") as f:
        json.dump(callgraph_sarif, f)
    return vuln_sarif, callgraph_sarif
