import asyncio
import json
import os
import uuid
from datetime import datetime, timezone

import redis.asyncio as redis
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from sqlalchemy import case, func
from sqlalchemy.orm import Session

import database
import models
from database import SessionLocal, get_db
from models import Job
from tasks import (
    ALLOWED_GEMINI_MODELS,
    DEFAULT_GEMINI_MODEL,
    DEV_LLM_CONFIG_KEY,
    SAMPLE_REPOS,
    run_pipeline,
)

app = FastAPI(title="HAST Pipeline API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development. Limit this in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / response schemas — existing public API
# ---------------------------------------------------------------------------

class JobRequest(BaseModel):
    repo_url: str
    submitted_by: str | None = None


class VulnFinding(BaseModel):
    message: str
    file: str
    code_snippet: str | None = None


class PipelineResult(BaseModel):
    repo: str
    vuln_msg: str
    vuln_file: str
    patch_generated: bool
    crash_hex: str | None = None
    patch_code: str | None = None


class JobSummary(BaseModel):
    task_id: str
    state: str
    repo_url: str | None = None
    submitted_at: str | None = None


class JobStatusResponse(BaseModel):
    task_id: str
    state: str
    vuln: VulnFinding | None = None
    result: PipelineResult | None = None


class DevLlmSettingsRequest(BaseModel):
    model: str = DEFAULT_GEMINI_MODEL
    api_key: str | None = None
    clear_api_key: bool = False
    bypass_llm: bool = False


class DevLlmSettingsResponse(BaseModel):
    model: str
    api_key_set: bool
    api_key_source: str | None = None
    bypass_llm: bool = False


class DevSampleRepo(BaseModel):
    url: str
    name: str
    description: str


class DevOptionsResponse(BaseModel):
    models: list[str]
    default_model: str
    llm: DevLlmSettingsResponse
    sample_repos: list[DevSampleRepo]


# ---------------------------------------------------------------------------
# Admin dashboard schemas
# ---------------------------------------------------------------------------

class AdminJobSummary(BaseModel):
    """One row in the admin job list / recent-jobs array."""
    model_config = ConfigDict(from_attributes=True)

    task_id: str
    repo_url: str
    submitted_by: str | None = None
    state: str
    submitted_at: datetime
    completed_at: datetime | None = None
    patch_generated: bool | None = None


class AdminJobDetail(BaseModel):
    """Full job record including vulnerability and patch fields."""
    model_config = ConfigDict(from_attributes=True)

    task_id: str
    repo_url: str
    submitted_by: str | None = None
    state: str
    submitted_at: datetime
    completed_at: datetime | None = None
    vuln_message: str | None = None
    vuln_file: str | None = None
    code_snippet: str | None = None
    patch_generated: bool | None = None
    crash_hex: str | None = None
    patch_code: str | None = None


class AdminDashboardResponse(BaseModel):
    """Aggregate stats plus the most recent 50 jobs."""
    total_jobs: int
    pending: int
    running: int
    succeeded: int
    failed: int
    recent_jobs: list[AdminJobSummary]


class AdminJobsListResponse(BaseModel):
    """Paginated, filterable job list."""
    total: int
    page: int
    page_size: int
    items: list[AdminJobSummary]


class UserStats(BaseModel):
    """Per-user job statistics."""
    submitted_by: str | None = None
    total_jobs: int
    succeeded: int
    failed: int
    last_submitted_at: datetime


class AdminUsersResponse(BaseModel):
    items: list[UserStats]


# ---------------------------------------------------------------------------
# Report endpoint schemas
# ---------------------------------------------------------------------------

class TaintNode(BaseModel):
    id: str
    label: str
    role: str
    file: str
    start_line: int
    start_col: int
    end_col: int


class TaintEdge(BaseModel):
    id: str
    source: str
    target: str


class TaintPath(BaseModel):
    nodes: list[TaintNode]
    edges: list[TaintEdge]


class CallPath(BaseModel):
    """Reachability chain main -> ... -> vulnerable function (same node/edge shape
    as TaintPath; roles map source=entry, intermediate=caller, sink=vulnerable fn)."""
    nodes: list[TaintNode]
    edges: list[TaintEdge]


class DiffPayload(BaseModel):
    original: str
    patched: str
    language: str


class CrashInfo(BaseModel):
    hex: str | None = None


class VulnSummary(BaseModel):
    message: str | None = None
    file: str | None = None
    rule_id: str | None = None


class ReportResponse(BaseModel):
    task_id: str
    repo_url: str
    state: str
    vuln_summary: VulnSummary
    taint_path: TaintPath
    call_path: CallPath
    diff: DiffPayload
    crash: CrashInfo


# ---------------------------------------------------------------------------
# In-memory job store (real-time WebSocket state)
# ---------------------------------------------------------------------------

job_store: dict[str, dict] = {}


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        await asyncio.gather(
            *[conn.send_text(message) for conn in self.active_connections],
            return_exceptions=True,
        )


manager = ConnectionManager()


# ---------------------------------------------------------------------------
# State update helpers
# ---------------------------------------------------------------------------

def _update_job_store(task_id: str, payload: dict) -> None:
    step = payload.get("step")
    status = payload.get("status")
    if step == "INIT" and status == "Running":
        job_store[task_id]["state"] = "STARTED"
    elif step == "PIPELINE" and status == "Success":
        job_store[task_id]["state"] = "SUCCESS"
    elif step == "PIPELINE" and status == "Failed":
        job_store[task_id]["state"] = "FAILURE"
    if "vuln" in payload and payload["vuln"] is not None:
        job_store[task_id]["vuln"] = payload["vuln"]
    if "result" in payload and payload["result"] is not None:
        job_store[task_id]["result"] = payload["result"]


def _db_sync_update(task_id: str, payload: dict) -> None:
    """Persist a pipeline status update to PostgreSQL (called in a thread pool)."""
    step = payload.get("step")
    status = payload.get("status")
    try:
        db = SessionLocal()
        job = db.query(Job).filter(Job.task_id == task_id).first()
        if not job:
            return
        if step == "INIT" and status == "Running":
            job.state = "STARTED"
        elif step == "PIPELINE" and status == "Success":
            job.state = "SUCCESS"
            job.completed_at = datetime.utcnow()
        elif step == "PIPELINE" and status == "Failed":
            job.state = "FAILURE"
            job.completed_at = datetime.utcnow()
        if payload.get("vuln"):
            v = payload["vuln"]
            job.vuln_message = v.get("message")
            job.vuln_file = v.get("file")
            job.code_snippet = v.get("code_snippet")
        if payload.get("result"):
            r = payload["result"]
            job.patch_generated = r.get("patch_generated")
            job.crash_hex = r.get("crash_hex")
            job.patch_code = r.get("patch_code")
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    database.init_db()
    url = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    app.state.redis = redis.from_url(url)
    app.state.pubsub = app.state.redis.pubsub()
    await app.state.pubsub.subscribe("pipeline_logs")
    asyncio.create_task(redis_listener())


async def redis_listener():
    while True:
        try:
            async for message in app.state.pubsub.listen():
                if message["type"] == "message":
                    raw = message["data"].decode("utf-8")
                    try:
                        payload = json.loads(raw)
                        task_id = payload.get("task_id")
                        if task_id and task_id in job_store:
                            _update_job_store(task_id, payload)
                            asyncio.get_event_loop().run_in_executor(
                                None, _db_sync_update, task_id, payload
                            )
                    except (json.JSONDecodeError, KeyError):
                        pass
                    await manager.broadcast(raw)
        except Exception:
            await asyncio.sleep(2)
            try:
                app.state.pubsub = app.state.redis.pubsub()
                await app.state.pubsub.subscribe("pipeline_logs")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Developer lab API
# ---------------------------------------------------------------------------

async def _read_dev_llm_config() -> dict:
    try:
        raw = await app.state.redis.get(DEV_LLM_CONFIG_KEY)
    except Exception:
        raw = None
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return {}


def _dev_llm_response(config: dict) -> DevLlmSettingsResponse:
    model = config.get("model") or os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    if model not in ALLOWED_GEMINI_MODELS:
        model = DEFAULT_GEMINI_MODEL
    redis_key_set = bool(config.get("api_key"))
    env_key_set = bool(os.environ.get("GEMINI_API_KEY"))
    return DevLlmSettingsResponse(
        model=model,
        api_key_set=redis_key_set or env_key_set,
        api_key_source="dev" if redis_key_set else ("env" if env_key_set else None),
        bypass_llm=bool(config.get("bypass_llm", False)),
    )


@app.get("/api/dev/options", response_model=DevOptionsResponse)
async def get_dev_options():
    config = await _read_dev_llm_config()
    samples = [
        DevSampleRepo(
            url=url,
            name=meta["name"],
            description=meta["description"],
        )
        for url, meta in SAMPLE_REPOS.items()
    ]
    return DevOptionsResponse(
        models=ALLOWED_GEMINI_MODELS,
        default_model=DEFAULT_GEMINI_MODEL,
        llm=_dev_llm_response(config),
        sample_repos=samples,
    )


@app.post("/api/dev/llm-settings", response_model=DevLlmSettingsResponse)
async def update_dev_llm_settings(settings: DevLlmSettingsRequest):
    if settings.model not in ALLOWED_GEMINI_MODELS:
        raise HTTPException(status_code=400, detail="Unsupported Gemini model")

    config = await _read_dev_llm_config()
    config["model"] = settings.model
    config["bypass_llm"] = settings.bypass_llm
    if settings.clear_api_key:
        config.pop("api_key", None)
    elif settings.api_key:
        config["api_key"] = settings.api_key.strip()

    await app.state.redis.set(DEV_LLM_CONFIG_KEY, json.dumps(config))
    return _dev_llm_response(config)


# ---------------------------------------------------------------------------
# Public job API (existing contracts — unchanged)
# ---------------------------------------------------------------------------

@app.post("/api/jobs")
async def submit_job(job: JobRequest):
    """
    POST /api/jobs

    Submit a new repository analysis job.

    Request body:
        repo_url     (str)           GitHub repository URL to analyse
        submitted_by (str, optional) User identifier (e.g. email). Stored for
                                     admin reporting; not used for auth.

    Response:
        message  (str) Confirmation message
        task_id  (str) UUID of the queued job
    """
    task_id = str(uuid.uuid4())
    job_store[task_id] = {
        "task_id": task_id,
        "state": "PENDING",
        "repo_url": job.repo_url,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "vuln": None,
        "result": None,
    }

    db = SessionLocal()
    try:
        db_job = Job(
            task_id=task_id,
            repo_url=job.repo_url,
            submitted_by=job.submitted_by,
            state="PENDING",
            submitted_at=datetime.utcnow(),
        )
        db.add(db_job)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    try:
        run_pipeline.apply_async((job.repo_url,), task_id=task_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Celery broker unavailable: {exc}")
    return {"message": "Job submitted successfully", "task_id": task_id}


@app.get("/api/jobs", response_model=list[JobSummary])
async def list_jobs():
    return [
        JobSummary(
            task_id=v["task_id"],
            state=v["state"],
            repo_url=v.get("repo_url"),
            submitted_at=v.get("submitted_at"),
        )
        for v in job_store.values()
    ]


@app.get("/api/jobs/{task_id}", response_model=JobStatusResponse)
async def get_job(task_id: str):
    if task_id not in job_store:
        raise HTTPException(status_code=404, detail="Job not found")
    entry = job_store[task_id]
    vuln = VulnFinding(**entry["vuln"]) if entry.get("vuln") else None
    result = PipelineResult(**entry["result"]) if entry.get("result") else None
    return JobStatusResponse(
        task_id=task_id,
        state=entry["state"],
        vuln=vuln,
        result=result,
    )


# ---------------------------------------------------------------------------
# Admin dashboard endpoints
# ---------------------------------------------------------------------------

@app.get("/admin/dashboard", response_model=AdminDashboardResponse)
def admin_dashboard(db: Session = Depends(get_db)):
    """
    GET /admin/dashboard

    Returns aggregate pipeline statistics and the 50 most recent jobs.

    Response:
        total_jobs  (int)               Total jobs ever submitted
        pending     (int)               Jobs in PENDING state
        running     (int)               Jobs in STARTED state
        succeeded   (int)               Jobs in SUCCESS state
        failed      (int)               Jobs in FAILURE state
        recent_jobs (AdminJobSummary[]) Up to 50 most recent jobs, newest first
    """
    counts = dict(
        db.query(Job.state, func.count(Job.id))
        .group_by(Job.state)
        .all()
    )
    recent = (
        db.query(Job)
        .order_by(Job.submitted_at.desc())
        .limit(50)
        .all()
    )
    return AdminDashboardResponse(
        total_jobs=sum(counts.values()),
        pending=counts.get("PENDING", 0),
        running=counts.get("STARTED", 0),
        succeeded=counts.get("SUCCESS", 0),
        failed=counts.get("FAILURE", 0),
        recent_jobs=[AdminJobSummary.model_validate(j) for j in recent],
    )


@app.get("/admin/dashboard/jobs", response_model=AdminJobsListResponse)
def admin_list_jobs(
    page: int = 1,
    page_size: int = 20,
    state: str | None = None,
    submitted_by: str | None = None,
    repo_url: str | None = None,
    db: Session = Depends(get_db),
):
    """
    GET /admin/dashboard/jobs

    Returns a paginated, filterable list of all jobs stored in PostgreSQL.

    Query params:
        page         (int, default=1)    Page number (1-indexed)
        page_size    (int, default=20)   Results per page (capped at 100)
        state        (str, optional)     Filter: PENDING | STARTED | SUCCESS | FAILURE
        submitted_by (str, optional)     Filter by exact submitted_by value
        repo_url     (str, optional)     Filter by repo_url substring (case-insensitive)

    Response:
        total     (int)               Total matching records
        page      (int)               Current page
        page_size (int)               Items per page
        items     (AdminJobSummary[]) Matching jobs, newest first
    """
    page_size = min(page_size, 100)
    q = db.query(Job)
    if state:
        q = q.filter(Job.state == state)
    if submitted_by:
        q = q.filter(Job.submitted_by == submitted_by)
    if repo_url:
        q = q.filter(Job.repo_url.ilike(f"%{repo_url}%"))

    total = q.count()
    jobs = (
        q.order_by(Job.submitted_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AdminJobsListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[AdminJobSummary.model_validate(j) for j in jobs],
    )


@app.get("/admin/dashboard/jobs/{task_id}", response_model=AdminJobDetail)
def admin_get_job(task_id: str, db: Session = Depends(get_db)):
    """
    GET /admin/dashboard/jobs/{task_id}

    Returns the full record for a single job, including SAST findings and patch.

    Path params:
        task_id (str) Job UUID

    Response fields:
        task_id         (str)       Job UUID
        repo_url        (str)       Target GitHub repository URL
        submitted_by    (str|null)  User identifier; null for anonymous submissions
        state           (str)       PENDING | STARTED | SUCCESS | FAILURE
        submitted_at    (datetime)  UTC timestamp of submission
        completed_at    (datetime)  UTC timestamp of pipeline completion, or null
        vuln_message    (str|null)  Vulnerability description from CodeQL SAST
        vuln_file       (str|null)  Relative file path of the vulnerability
        code_snippet    (str|null)  First 500 chars of the vulnerable source code
        patch_generated (bool|null) True when a patch was successfully generated
        crash_hex       (str|null)  AFL++ crash input encoded as hexadecimal
        patch_code      (str|null)  LLM-generated patch source code

    Errors:
        404  Job not found
    """
    job = db.query(Job).filter(Job.task_id == task_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return AdminJobDetail.model_validate(job)


@app.get("/api/jobs/{task_id}/report", response_model=ReportResponse)
def get_report(task_id: str, db: Session = Depends(get_db)):
    """
    GET /api/jobs/{task_id}/report

    Returns the full vulnerability report for a completed job, including the
    SARIF taint-flow path (as {nodes, edges}) and the original-vs-patch diff.

    Path params:
        task_id (str) Job UUID

    Response:
        task_id      (str)         Job UUID
        repo_url     (str)         Target repository URL
        state        (str)         SUCCESS (guaranteed for a successful 200)
        vuln_summary              message, file, rule_id (null until stored)
        taint_path                nodes[] and edges[] derived from SARIF codeFlows
        diff                      original and patched full source; language id
        crash                     hex-encoded AFL++ crash input, or null

    Errors:
        404  Job not found
        409  Job not complete — check X-Job-State response header for current state
    """
    job = db.query(Job).filter(Job.task_id == task_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.state != "SUCCESS":
        raise HTTPException(
            status_code=409,
            detail="Job not complete",
            headers={"X-Job-State": job.state},
        )

    ext = (job.vuln_file or "").rsplit(".", 1)[-1].lower()
    lang = {"c": "c", "h": "c", "cpp": "cpp", "cc": "cpp",
            "cxx": "cpp", "hpp": "cpp"}.get(ext, "plaintext")

    raw_path = job.taint_path or {"nodes": [], "edges": []}
    raw_call = job.call_path or {"nodes": [], "edges": []}
    return ReportResponse(
        task_id=job.task_id,
        repo_url=job.repo_url,
        state=job.state,
        vuln_summary=VulnSummary(
            message=job.vuln_message,
            file=job.vuln_file,
            rule_id=None,
        ),
        taint_path=TaintPath(
            nodes=[TaintNode(**n) for n in raw_path.get("nodes", [])],
            edges=[TaintEdge(**e) for e in raw_path.get("edges", [])],
        ),
        call_path=CallPath(
            nodes=[TaintNode(**n) for n in raw_call.get("nodes", [])],
            edges=[TaintEdge(**e) for e in raw_call.get("edges", [])],
        ),
        diff=DiffPayload(
            original=job.original_code or job.code_snippet or "",
            patched=job.patch_code or "",
            language=lang,
        ),
        crash=CrashInfo(hex=job.crash_hex),
    )


@app.get("/admin/dashboard/users", response_model=AdminUsersResponse)
def admin_list_users(db: Session = Depends(get_db)):
    """
    GET /admin/dashboard/users

    Returns per-user job statistics, ordered by most recent activity.
    Anonymous submissions (submitted_by=null) are grouped together as one entry.

    Response — list of UserStats:
        submitted_by      (str|null)  User identifier; null = anonymous
        total_jobs        (int)       Total jobs submitted by this user
        succeeded         (int)       Jobs that reached SUCCESS state
        failed            (int)       Jobs that reached FAILURE state
        last_submitted_at (datetime)  Most recent submission timestamp
    """
    rows = (
        db.query(
            Job.submitted_by,
            func.count(Job.id).label("total_jobs"),
            func.sum(case((Job.state == "SUCCESS", 1), else_=0)).label("succeeded"),
            func.sum(case((Job.state == "FAILURE", 1), else_=0)).label("failed"),
            func.max(Job.submitted_at).label("last_submitted_at"),
        )
        .group_by(Job.submitted_by)
        .order_by(func.max(Job.submitted_at).desc())
        .all()
    )
    return AdminUsersResponse(
        items=[
            UserStats(
                submitted_by=r.submitted_by,
                total_jobs=r.total_jobs,
                succeeded=r.succeeded or 0,
                failed=r.failed or 0,
                last_submitted_at=r.last_submitted_at,
            )
            for r in rows
        ]
    )


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Client payload processing can be done here
    except WebSocketDisconnect:
        manager.disconnect(websocket)
