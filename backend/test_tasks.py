"""Unit tests for the SARIF -> graph helpers in tasks.py.

tasks.py imports heavyweight runtime deps (celery, docker, redis, google-genai)
at module load. These tests only exercise the pure SARIF-parsing helpers, so we
stub those modules in sys.modules before importing tasks — no broker, Docker
daemon, or API key required.
"""
import sys
from unittest.mock import MagicMock

for _name in [
    "celery", "redis", "docker", "requests",
    "rich", "rich.console", "rich.markup",
    "google", "google.genai",
]:
    sys.modules.setdefault(_name, MagicMock())

import tasks  # noqa: E402


# --------------------------------------------------------------------------- #
# _extract_taint_path
# --------------------------------------------------------------------------- #
def _thread_flow(steps):
    """Build a SARIF result with one codeFlow/threadFlow from (label, line) steps."""
    locations = [
        {
            "location": {
                "message": {"text": label},
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/main.c"},
                    "region": {"startLine": line, "startColumn": 1, "endColumn": 9},
                },
            }
        }
        for label, line in steps
    ]
    return {"codeFlows": [{"threadFlows": [{"locations": locations}]}]}


def test_extract_taint_path_roles_and_edges():
    result = _thread_flow([("input", 5), ("buf", 6), ("strcpy(buf, input)", 7)])
    path = tasks._extract_taint_path(result)

    assert [n["role"] for n in path["nodes"]] == ["source", "intermediate", "sink"]
    assert [n["label"] for n in path["nodes"]] == ["input", "buf", "strcpy(buf, input)"]
    assert path["nodes"][-1]["start_line"] == 7
    assert len(path["edges"]) == 2
    assert path["edges"][0] == {"id": "edge-0-1", "source": "node-0", "target": "node-1"}


def test_extract_taint_path_empty_without_codeflows():
    assert tasks._extract_taint_path({"message": {"text": "x"}}) == {"nodes": [], "edges": []}


# --------------------------------------------------------------------------- #
# _extract_call_path
# --------------------------------------------------------------------------- #
def _call_edge(caller, callee, line):
    return {
        "ruleId": tasks.CALL_EDGE_RULE_ID,
        "message": {"text": f"CALL_EDGE {caller} -> {callee}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/main.c"},
            "region": {"startLine": line},
        }}],
    }


def test_extract_call_path_bfs_main_to_vuln():
    edges = [
        _call_edge("main", "vulnerable_func", 7),
        _call_edge("vulnerable_func", "strcpy", 4),
    ]
    path = tasks._extract_call_path(edges, sink_line=4)

    assert [n["label"] for n in path["nodes"]] == ["main", "vulnerable_func"]
    assert [n["role"] for n in path["nodes"]] == ["source", "sink"]
    assert path["nodes"][0]["start_line"] == 7  # call site main -> vulnerable_func
    assert len(path["edges"]) == 1
    assert path["edges"][0]["source"] == "call-0"
    assert path["edges"][0]["target"] == "call-1"


def test_extract_call_path_shortest_chain():
    edges = [
        _call_edge("main", "a", 2),
        _call_edge("a", "b", 3),
        _call_edge("b", "vuln", 4),
        _call_edge("main", "vuln", 9),   # a direct shorter route
        _call_edge("vuln", "strcpy", 5),
    ]
    path = tasks._extract_call_path(edges, sink_line=5)
    assert [n["label"] for n in path["nodes"]] == ["main", "vuln"]


def test_extract_call_path_unreachable_returns_vuln_alone():
    edges = [
        _call_edge("helper", "vulnerable_func", 7),
        _call_edge("vulnerable_func", "strcpy", 4),
    ]
    path = tasks._extract_call_path(edges, sink_line=4)
    assert len(path["nodes"]) == 1
    assert path["nodes"][0]["label"] == "vulnerable_func"
    assert path["nodes"][0]["role"] == "sink"
    assert path["edges"] == []


def test_extract_call_path_empty_without_edges():
    assert tasks._extract_call_path([]) == {"nodes": [], "edges": []}


def test_extract_call_path_structural_via_related_locations():
    """No dangerous-call sink; fall back to a function named in relatedLocations."""
    edges = [_call_edge("main", "bootp_print", 120)]
    vuln_result = {"relatedLocations": [{"message": {"text": "bootp_print"}}]}
    path = tasks._extract_call_path(edges, vuln_result=vuln_result)
    assert [n["label"] for n in path["nodes"]] == ["main", "bootp_print"]
