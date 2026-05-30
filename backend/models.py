from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

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
