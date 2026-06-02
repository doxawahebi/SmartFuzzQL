import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
from database import Base, get_db
from main import app
from models import Job

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_review_mode.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    monkeypatch.setenv("PIPELINE_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _db():
    return TestingSessionLocal()


def test_plain_repo_job_keeps_auto_pipeline(client, monkeypatch):
    called = {}

    def fake_auto(args, task_id=None):
        called["auto"] = {"args": args, "task_id": task_id}

    def fake_review(task_id, stage):
        called["review"] = {"task_id": task_id, "stage": stage}

    monkeypatch.setattr(main.run_pipeline, "apply_async", fake_auto)
    monkeypatch.setattr(main, "enqueue_review_stage", fake_review)

    res = client.post("/api/jobs", json={"repo_url": "sample://buffer-overflow"})
    assert res.status_code == 200
    task_id = res.json()["task_id"]
    assert called["auto"]["args"] == ("sample://buffer-overflow",)
    assert called["auto"]["task_id"] == task_id
    assert "review" not in called


def test_review_repo_job_enqueues_init_stage(client, monkeypatch):
    called = {}

    def fake_review(task_id, stage):
        called["review"] = {"task_id": task_id, "stage": stage}

    monkeypatch.setattr(main, "enqueue_review_stage", fake_review)

    res = client.post(
        "/api/jobs",
        json={"target_type": "repo", "repo_url": "sample://buffer-overflow", "review_mode": True},
    )
    assert res.status_code == 200
    task_id = res.json()["task_id"]
    assert called["review"] == {"task_id": task_id, "stage": "INIT"}

    db = _db()
    job = db.query(Job).filter(Job.task_id == task_id).first()
    db.close()
    assert job.review_mode is True
    assert job.current_stage == "INIT"
    assert job.review_state == "queued"
    assert os.path.isdir(job.workspace_path)


def test_review_source_job_writes_inline_source(client, monkeypatch):
    monkeypatch.setattr(main, "enqueue_review_stage", lambda task_id, stage: None)
    source = "void f(char *s) { char b[8]; strcpy(b, s); }"

    res = client.post(
        "/api/jobs",
        json={"target_type": "source", "source_code": source, "review_mode": True},
    )
    assert res.status_code == 200
    task_id = res.json()["task_id"]

    db = _db()
    job = db.query(Job).filter(Job.task_id == task_id).first()
    db.close()
    assert job.repo_url == f"inline://{task_id}"
    assert job.target_type == "source"
    with open(os.path.join(job.workspace_path, "inline_source.c"), encoding="utf-8") as f:
        assert f.read() == source


def test_approve_waiting_stage_enqueues_next(client, monkeypatch):
    called = {}
    monkeypatch.setattr(main, "enqueue_review_stage", lambda task_id, stage: called.setdefault("stage", stage))
    monkeypatch.setattr(main, "notify_status", lambda *args, **kwargs: None)
    db = _db()
    job = Job(
        task_id="review-job",
        repo_url="sample://buffer-overflow",
        state="STARTED",
        review_mode=True,
        target_type="repo",
        current_stage="SAST",
        review_state="waiting",
        stage_results={},
        stage_artifacts={"SAST": {"type": "sast"}},
    )
    db.add(job)
    db.commit()
    db.close()

    res = client.post("/api/jobs/review-job/review/approve")
    assert res.status_code == 200
    assert res.json()["next_stage"] == "AI_HARNESS"
    assert called["stage"] == "AI_HARNESS"


def test_retry_waiting_stage_clears_downstream(client, monkeypatch):
    called = {}
    monkeypatch.setattr(main, "enqueue_review_stage", lambda task_id, stage: called.setdefault("stage", stage))
    monkeypatch.setattr(main, "notify_status", lambda *args, **kwargs: None)
    db = _db()
    job = Job(
        task_id="retry-job",
        repo_url="sample://buffer-overflow",
        state="STARTED",
        review_mode=True,
        target_type="repo",
        current_stage="DAST",
        review_state="waiting",
        stage_results={"sast": {}, "harness": {}, "dast": {}, "patch": {}},
        stage_artifacts={"SAST": {}, "AI_HARNESS": {}, "DAST": {}, "AI_PATCH": {}},
        crash_hex="deadbeef",
        patch_generated=True,
        patch_code="patched",
    )
    db.add(job)
    db.commit()
    db.close()

    res = client.post("/api/jobs/retry-job/review/retry")
    assert res.status_code == 200
    assert called["stage"] == "DAST"

    db = _db()
    refreshed = db.query(Job).filter(Job.task_id == "retry-job").first()
    db.close()
    assert "dast" not in refreshed.stage_results
    assert "patch" not in refreshed.stage_results
    assert "DAST" not in refreshed.stage_artifacts
    assert refreshed.crash_hex is None
    assert refreshed.patch_code is None
    assert refreshed.review_state == "retrying"


def test_retry_sast_removes_codeql_outputs(client, monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(main, "enqueue_review_stage", lambda task_id, stage: called.setdefault("stage", stage))
    monkeypatch.setattr(main, "notify_status", lambda *args, **kwargs: None)
    workspace = tmp_path / "workspace"
    (workspace / "my-db").mkdir(parents=True)
    (workspace / "results.sarif").write_text("{}", encoding="utf-8")
    (workspace / "callgraph.sarif").write_text("{}", encoding="utf-8")
    (workspace / "src.c").write_text("int main(void) { return 0; }", encoding="utf-8")
    db = _db()
    job = Job(
        task_id="retry-sast-files",
        repo_url="sample://buffer-overflow",
        state="STARTED",
        review_mode=True,
        target_type="repo",
        workspace_path=str(workspace),
        current_stage="SAST",
        review_state="waiting",
        stage_results={"sast": {}},
        stage_artifacts={"SAST": {}},
    )
    db.add(job)
    db.commit()
    db.close()

    res = client.post("/api/jobs/retry-sast-files/review/retry")
    assert res.status_code == 200
    assert called["stage"] == "SAST"
    assert not (workspace / "my-db").exists()
    assert not (workspace / "results.sarif").exists()
    assert not (workspace / "callgraph.sarif").exists()
    assert (workspace / "src.c").exists()


def test_approve_requires_waiting_state(client):
    db = _db()
    job = Job(
        task_id="not-waiting",
        repo_url="sample://buffer-overflow",
        state="STARTED",
        review_mode=True,
        target_type="repo",
        current_stage="SAST",
        review_state="running",
    )
    db.add(job)
    db.commit()
    db.close()

    res = client.post("/api/jobs/not-waiting/review/approve")
    assert res.status_code == 409


def test_approve_rejects_stage_mismatch(client):
    db = _db()
    job = Job(
        task_id="stage-mismatch",
        repo_url="sample://buffer-overflow",
        state="STARTED",
        review_mode=True,
        target_type="repo",
        current_stage="DAST",
        review_state="waiting",
    )
    db.add(job)
    db.commit()
    db.close()

    res = client.post("/api/jobs/stage-mismatch/review/approve", json={"stage": "SAST"})
    assert res.status_code == 409
