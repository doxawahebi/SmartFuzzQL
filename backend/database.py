import os
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@db:5432/hast_db")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    import models  # noqa: F401 — registers Job model with Base
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        for col, typedef in [
            ("original_code", "TEXT"),
            ("taint_path", "JSONB"),
            ("call_path", "JSONB"),
            ("review_mode", "BOOLEAN DEFAULT FALSE NOT NULL"),
            ("target_type", "VARCHAR(20) DEFAULT 'repo' NOT NULL"),
            ("workspace_path", "TEXT"),
            ("current_stage", "VARCHAR(40)"),
            ("review_state", "VARCHAR(40)"),
            ("stage_results", "JSONB"),
            ("stage_artifacts", "JSONB"),
            ("failure_detail", "TEXT"),
        ]:
            conn.execute(text(
                f"ALTER TABLE jobs ADD COLUMN IF NOT EXISTS {col} {typedef}"
            ))
        conn.commit()
