from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Text

from database import Base


class Job(Base):
    __tablename__ = "jobs"

    id              = Column(Integer, primary_key=True, index=True)
    task_id         = Column(String(36), unique=True, nullable=False, index=True)
    repo_url        = Column(Text, nullable=False)
    submitted_by    = Column(String(255), nullable=True, index=True)
    state           = Column(String(20), nullable=False, default="PENDING")
    submitted_at    = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at    = Column(DateTime, nullable=True)
    vuln_message    = Column(Text, nullable=True)
    vuln_file       = Column(Text, nullable=True)
    code_snippet    = Column(Text, nullable=True)
    patch_generated = Column(Boolean, nullable=True)
    crash_hex       = Column(Text, nullable=True)
    patch_code      = Column(Text, nullable=True)
    original_code   = Column(Text, nullable=True)
    taint_path      = Column(JSON, nullable=True)
    call_path       = Column(JSON, nullable=True)
    review_mode     = Column(Boolean, nullable=False, default=False)
    target_type     = Column(String(20), nullable=False, default="repo")
    workspace_path  = Column(Text, nullable=True)
    current_stage   = Column(String(40), nullable=True)
    review_state    = Column(String(40), nullable=True)
    stage_results   = Column(JSON, nullable=True)
    stage_artifacts = Column(JSON, nullable=True)
    failure_detail  = Column(Text, nullable=True)
