"""Unit tests for the Joern -> SARIF adapter in joern_analysis.py.

The whole point of the adapter is that Joern findings become indistinguishable
from CodeQL findings to the rest of the pipeline. So these tests feed a sample
``joern_raw.json`` through ``joern_raw_to_sarif`` and then run the *real* downstream
parsers from tasks.py over the output, asserting they produce correct vuln
metadata, taint paths, and call paths.

tasks.py pulls in heavyweight runtime deps at import; we stub them (same approach
as test_tasks.py) so no broker/Docker/API key is needed.
"""

import sys
from unittest.mock import MagicMock

for _name in [
    "celery",
    "redis",
    "docker",
    "requests",
    "rich",
    "rich.console",
    "rich.markup",
    "google",
    "google.genai",
]:
    sys.modules.setdefault(_name, MagicMock())

import joern_analysis  # noqa: E402
import tasks  # noqa: E402

IMPORT_ROOT = "/tmp/pipeline_run_x/repo"


def _sample_raw():
    """A taint flow (param `name` -> strcpy dest) plus the call edges main -> copy_it
    -> strcpy, with the strcpy call site on the sink line (line 12)."""
    return {
        "findings": [
            {
                "message": "tainted value reaches strcpy",
                "sink": {
                    "file": f"{IMPORT_ROOT}/src/vuln.c",
                    "line": 12,
                    "col": 3,
                    "endCol": 20,
                },
                "flow": [
                    {
                        "code": "char *name",
                        "file": f"{IMPORT_ROOT}/src/vuln.c",
                        "line": 8,
                        "col": 10,
                        "endCol": 14,
                    },
                    {
                        "code": "strcpy(buf, name)",
                        "file": f"{IMPORT_ROOT}/src/vuln.c",
                        "line": 12,
                        "col": 3,
                        "endCol": 20,
                    },
                ],
            }
        ],
        "call_edges": [
            {
                "caller": "main",
                "callee": "copy_it",
                "file": f"{IMPORT_ROOT}/src/vuln.c",
                "line": 20,
            },
            {
                "caller": "copy_it",
                "callee": "strcpy",
                "file": f"{IMPORT_ROOT}/src/vuln.c",
                "line": 12,
            },
        ],
    }


def test_vuln_sarif_is_consumable_by_select_vulnerability():
    vuln_sarif, _ = joern_analysis.joern_raw_to_sarif(_sample_raw(), IMPORT_ROOT)
    results = vuln_sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "cpp/taint-buffer-overflow"
    assert results[0]["level"] == "error"

    msg, file, line = tasks._select_vulnerability(results)
    assert "strcpy" in msg
    # URI must be repo-relative (import root stripped) so _read_vulnerable_code joins ok.
    assert file == "src/vuln.c"
    assert line == 12


def test_taint_path_extraction_matches_codeql_shape():
    vuln_sarif, _ = joern_analysis.joern_raw_to_sarif(_sample_raw(), IMPORT_ROOT)
    results = vuln_sarif["runs"][0]["results"]

    # _select_taint_result prefers a result with codeFlows.
    taint_result = next((r for r in results if r.get("codeFlows")), None)
    assert taint_result is not None

    path = tasks._extract_taint_path(taint_result)
    assert [n["role"] for n in path["nodes"]] == ["source", "sink"]
    assert path["nodes"][0]["label"] == "char *name"
    assert path["nodes"][0]["start_line"] == 8
    assert path["nodes"][-1]["start_line"] == 12
    assert path["nodes"][0]["file"] == "src/vuln.c"
    assert len(path["edges"]) == 1


def test_call_edges_drive_call_path_bfs():
    _, callgraph_sarif = joern_analysis.joern_raw_to_sarif(_sample_raw(), IMPORT_ROOT)
    call_results = callgraph_sarif["runs"][0]["results"]

    edges, locs = tasks._parse_call_edges(call_results)
    assert ("main", "copy_it") in edges
    assert ("copy_it", "strcpy") in edges
    assert locs[("copy_it", "strcpy")] == ("src/vuln.c", 12)

    # BFS main -> copy_it (the function that calls the dangerous strcpy on the sink line).
    call_path = tasks._extract_call_path(call_results, vuln_result=None, sink_line=12)
    labels = [n["label"] for n in call_path["nodes"]]
    assert labels == ["main", "copy_it"]
    assert call_path["nodes"][0]["role"] == "source"
    assert call_path["nodes"][-1]["role"] == "sink"


def test_absolute_and_already_relative_paths_normalize():
    assert joern_analysis._rel_uri(f"{IMPORT_ROOT}/a/b.c", IMPORT_ROOT) == "a/b.c"
    # A path already relative (Joern sometimes emits import-root-relative names) is kept.
    assert joern_analysis._rel_uri("a/b.c", IMPORT_ROOT) == "a/b.c"
    # Leading slash without the root prefix is stripped to stay join-safe.
    assert joern_analysis._rel_uri("/a/b.c", IMPORT_ROOT) == "a/b.c"
    assert joern_analysis._rel_uri("", IMPORT_ROOT) == ""


def test_empty_raw_yields_valid_empty_sarif():
    vuln_sarif, callgraph_sarif = joern_analysis.joern_raw_to_sarif({}, IMPORT_ROOT)
    assert vuln_sarif["runs"][0]["results"] == []
    assert callgraph_sarif["runs"][0]["results"] == []
    # Downstream "nothing found" path stays graceful.
    msg, file, line = tasks._select_vulnerability(vuln_sarif["runs"][0]["results"])
    assert file == "unknown"
    assert line is None


def test_finding_without_flow_has_no_codeflows():
    raw = {
        "findings": [
            {"message": "m", "sink": {"file": f"{IMPORT_ROOT}/x.c", "line": 5}}
        ]
    }
    vuln_sarif, _ = joern_analysis.joern_raw_to_sarif(raw, IMPORT_ROOT)
    result = vuln_sarif["runs"][0]["results"][0]
    assert "codeFlows" not in result
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "x.c"
    )
