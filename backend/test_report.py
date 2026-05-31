"""Tests for GET /api/jobs/{task_id}/report endpoint."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from main import app
from models import Job

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_report.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _seed_job(db, task_id: str, state: str = "SUCCESS", **kwargs):
    job = Job(
        task_id=task_id,
        repo_url="https://github.com/example/repo",
        state=state,
        vuln_message="Potential buffer overflow",
        vuln_file="src/vuln.c",
        **kwargs,
    )
    db.add(job)
    db.commit()
    return job


def test_report_success(client):
    db = TestingSessionLocal()
    _seed_job(
        db,
        task_id="test-uuid-1",
        original_code="void f(char* s) { char buf[10]; strcpy(buf, s); }",
        patch_code="void f(char* s) { char buf[10]; strncpy(buf, s, 9); buf[9] = 0; }",
        crash_hex="deadbeef",
        taint_path={
            "nodes": [
                {"id": "node-0", "label": "s", "role": "source", "file": "src/vuln.c", "start_line": 1, "start_col": 13, "end_col": 14},
                {"id": "node-1", "label": "strcpy sink", "role": "sink", "file": "src/vuln.c", "start_line": 1, "start_col": 28, "end_col": 33},
            ],
            "edges": [{"id": "edge-0-1", "source": "node-0", "target": "node-1"}],
        },
        call_path={
            "nodes": [
                {"id": "call-0", "label": "main", "role": "source", "file": "src/vuln.c", "start_line": 9, "start_col": 0, "end_col": 0},
                {"id": "call-1", "label": "f", "role": "sink", "file": "src/vuln.c", "start_line": 9, "start_col": 0, "end_col": 0},
            ],
            "edges": [{"id": "call-edge-0-1", "source": "call-0", "target": "call-1"}],
        },
    )
    db.close()

    r = client.get("/api/jobs/test-uuid-1/report")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "SUCCESS"
    assert body["taint_path"]["nodes"][0]["role"] == "source"
    assert body["taint_path"]["nodes"][1]["role"] == "sink"
    assert body["call_path"]["nodes"][0]["label"] == "main"
    assert body["call_path"]["nodes"][0]["role"] == "source"
    assert body["call_path"]["nodes"][-1]["role"] == "sink"
    assert body["diff"]["language"] == "c"
    assert body["diff"]["original"].startswith("void f")
    assert body["crash"]["hex"] == "deadbeef"


def test_report_not_found(client):
    r = client.get("/api/jobs/nonexistent/report")
    assert r.status_code == 404


def test_report_job_not_complete(client):
    db = TestingSessionLocal()
    _seed_job(db, task_id="test-uuid-2", state="STARTED")
    db.close()

    r = client.get("/api/jobs/test-uuid-2/report")
    assert r.status_code == 409
    assert r.headers["x-job-state"] == "STARTED"


def test_report_language_detection(client):
    db = TestingSessionLocal()
    _seed_job(db, task_id="test-uuid-cpp", vuln_file="src/main.cpp",
              original_code="int main(){}", patch_code="int main(){return 0;}")
    db.close()

    r = client.get("/api/jobs/test-uuid-cpp/report")
    assert r.status_code == 200
    assert r.json()["diff"]["language"] == "cpp"


def test_report_empty_taint_path(client):
    db = TestingSessionLocal()
    _seed_job(db, task_id="test-uuid-no-path", original_code="x", patch_code="y")
    db.close()

    r = client.get("/api/jobs/test-uuid-no-path/report")
    assert r.status_code == 200
    body = r.json()
    assert body["taint_path"]["nodes"] == []
    assert body["taint_path"]["edges"] == []
    assert body["call_path"]["nodes"] == []
    assert body["call_path"]["edges"] == []
