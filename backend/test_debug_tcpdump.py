"""Unit test for the DEBUG_TEST_TCPDUMP resilience mode (debug_tcpdump.py).

Verifies the wiring end-to-end with `tasks._run_pipeline_impl`: every real stage is forced
to fail, and debug_tcpdump's patches carry the job to a SUCCESS bootp_print report:

  - SAST  -> real bootp_sa.sarif is dropped in (CodeQL forced to fail).
  - DAST  -> the real fuzzing fallback (fuzz_known_good_harness) needs a Docker daemon +
             AFL++, which a unit test cannot run, so it is mocked to return crash bytes.
             (The real build-tcpdump + compile harness.c + AFL++ fuzz path is verified
             live via `docker compose` with DEBUG_TEST_TCPDUMP=True — see backend/CLAUDE.md.)
  - LLM   -> harness/patch fall back to the bundled artifacts on error.

tasks.py contains no mock logic; debug_tcpdump patches its boundary functions on import.
Heavy deps are stubbed so no broker/Docker/API key is needed; DATABASE_URL points at SQLite
before importing database so the pipeline's SessionLocal writes where the report reads.
DEBUG_BYPASS_LLM is intentionally left unset (the two flags are independent).
"""
import os
import sys
from unittest.mock import MagicMock

os.environ["DATABASE_URL"] = "sqlite:///./test_debug_tcpdump.db"
os.environ["DEBUG_TEST_TCPDUMP"] = "True"
os.environ.pop("DEBUG_BYPASS_LLM", None)
os.environ.pop("GEMINI_API_KEY", None)

for _name in [
    "celery", "redis", "redis.asyncio", "docker", "requests",
    "rich", "rich.console", "rich.markup",
    "google", "google.genai",
]:
    sys.modules.setdefault(_name, MagicMock())

import subprocess  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import database  # noqa: E402
from database import Base  # noqa: E402
from models import Job  # noqa: E402
from main import app  # noqa: E402
import tasks  # noqa: E402
import debug_tcpdump as dbg  # noqa: E402  (auto-activates: patches tasks boundaries)

TASK_ID = "tcpdump-debug-1"
FAKE_CRASH = b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00"  # stand-in for a fuzz-found crash


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=database.engine)
    yield
    Base.metadata.drop_all(bind=database.engine)


@pytest.fixture
def client():
    return TestClient(app)  # no context manager: skip the Postgres-only startup init_db()


def _force_real_stages_to_fail(monkeypatch):
    """Force clone + CodeQL + the LLM-harness DAST to fail, and mock the real fuzzing
    fallback (which needs Docker) so the path is exercised deterministically."""
    monkeypatch.setattr(tasks.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(subprocess.CalledProcessError(1, "git")))
    monkeypatch.setattr(tasks.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("no codeql")))
    monkeypatch.setattr(tasks, "build_dynamic_fuzzing_env", lambda *a, **k: (_ for _ in ()).throw(Exception("no docker")))
    # Real fuzzing (build tcpdump + harness.c + AFL++) is verified live in docker compose;
    # here we stand in for the crash it would find.
    monkeypatch.setattr(dbg, "fuzz_known_good_harness", lambda task_id, repo_url, *a, **k: FAKE_CRASH)


def test_debug_tcpdump_active_and_independent_of_bypass_llm():
    assert dbg.is_enabled() is True
    assert os.environ.get("DEBUG_BYPASS_LLM") is None
    assert getattr(tasks, "_tcpdump_debug_active", False) is True


def test_pipeline_falls_back_and_reports_success(client, monkeypatch):
    _force_real_stages_to_fail(monkeypatch)

    db = database.SessionLocal()
    db.add(Job(task_id=TASK_ID, repo_url=dbg.TCPDUMP_REPO_URL, state="PENDING"))
    db.commit()
    db.close()

    tasks._run_pipeline_impl(TASK_ID, dbg.TCPDUMP_REPO_URL)

    r = client.get(f"/api/jobs/{TASK_ID}/report")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["state"] == "SUCCESS"
    assert body["vuln_summary"]["file"] == "print-bootp.c"          # from real bootp_sa.sarif
    assert "ND_TCHECK" in body["vuln_summary"]["message"]
    assert body["crash"]["hex"] == FAKE_CRASH.hex()                  # crash flows from the fuzzing fallback
    assert body["diff"]["patched"].strip() != ""
