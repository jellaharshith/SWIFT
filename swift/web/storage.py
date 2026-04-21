"""SQLAlchemy storage for SWIFT scan history (PostgreSQL or SQLite)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, Float, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from agent.models import ScanResult
from log.logger import get_logger

logger = get_logger("web.storage")

# DATABASE_URL takes precedence (Railway/Heroku PostgreSQL).
# Fallback: SQLite for local dev.
_DATABASE_URL = os.environ.get("DATABASE_URL")
_DB_PATH = os.environ.get("SWIFT_DB_PATH", "./swift_scans.db")


class Base(DeclarativeBase):
    pass


class ScanJob(Base):
    """ORM model for tracking in-progress scan jobs (status, progress, errors)."""

    __tablename__ = "scan_jobs"

    job_id = Column(String, primary_key=True)
    status = Column(String, nullable=False)  # "queued", "running", "done", "error"
    stage = Column(Integer, default=0)
    stage_name = Column(String, default="")
    files_total = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    current_file = Column(String, default="")
    detail = Column(String, nullable=True)  # scan_id when done, error message when error
    # Extended progress fields
    progress = Column(Integer, default=0, nullable=True)          # 0–100 percent
    signals_detected = Column(Integer, default=0, nullable=True)
    batch_current = Column(Integer, default=0, nullable=True)
    batch_total = Column(Integer, default=0, nullable=True)
    started_at = Column(String, nullable=True)                    # ISO timestamp
    findings_json = Column(Text, nullable=True)                   # JSON array of partial findings


class ScanRecord(Base):
    """ORM model representing a persisted scan result."""

    __tablename__ = "scan_records"

    scan_id = Column(String, primary_key=True)
    repo_path = Column(String, nullable=False)
    files_scanned = Column(Integer, nullable=False)
    vuln_count = Column(Integer, nullable=False)
    patch_count = Column(Integer, nullable=False)
    duration_seconds = Column(Float, nullable=False)
    cost_usd = Column(Float, nullable=False)
    timestamp = Column(String, nullable=False)
    raw_json = Column(String, nullable=False)


def _scan_result_to_dict(result: ScanResult) -> dict:
    """Recursively convert a ScanResult dataclass to a plain dict.

    Args:
        result: The ScanResult dataclass instance to serialize.

    Returns:
        A plain dict with all nested dataclass fields converted.
    """
    return asdict(result)


def init_db(engine) -> None:
    """Create all tables if they do not exist.

    Args:
        engine: SQLAlchemy engine instance connected to the target database.
    """
    Base.metadata.create_all(engine)
    logger.info("Database tables initialized.")


def save_scan(session: Session, scan_result: ScanResult) -> ScanRecord:
    """Persist a ScanResult to the database.

    Args:
        session: Active SQLAlchemy session.
        scan_result: Completed scan result to store.

    Returns:
        The newly created ScanRecord ORM object.
    """
    raw = json.dumps(_scan_result_to_dict(scan_result))
    record = ScanRecord(
        scan_id=scan_result.scan_id,
        repo_path=scan_result.repo_path,
        files_scanned=scan_result.files_scanned,
        vuln_count=len(scan_result.vulnerabilities),
        patch_count=len(scan_result.patches),
        duration_seconds=scan_result.duration_seconds,
        cost_usd=scan_result.total_cost_usd,
        timestamp=scan_result.timestamp,
        raw_json=raw,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    logger.info("Saved scan %s to database.", scan_result.scan_id)
    return record


def get_scans(session: Session, limit: int = 50, offset: int = 0) -> List[ScanRecord]:
    """Retrieve a paginated list of scan records ordered by timestamp descending.

    Args:
        session: Active SQLAlchemy session.
        limit: Maximum number of records to return.
        offset: Number of records to skip before returning results.

    Returns:
        List of ScanRecord objects.
    """
    return (
        session.query(ScanRecord)
        .order_by(ScanRecord.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_scan(session: Session, scan_id: str) -> Optional[ScanRecord]:
    """Retrieve a single scan record by its scan ID.

    Args:
        session: Active SQLAlchemy session.
        scan_id: Unique scan identifier (e.g. "SWIFT-20240115-001").

    Returns:
        The matching ScanRecord or None if not found.
    """
    return session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()


def create_scan_job(session: Session, job_id: str) -> ScanJob:
    """Create a new scan job record in queued state.

    Args:
        session: Active SQLAlchemy session.
        job_id: Unique job identifier.

    Returns:
        The newly created ScanJob record.
    """
    job = ScanJob(
        job_id=job_id,
        status="queued",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    session.add(job)
    session.commit()
    return job


def update_scan_job(session: Session, job_id: str, **kwargs) -> Optional[ScanJob]:
    """Update scan job progress or status.

    Args:
        session: Active SQLAlchemy session.
        job_id: Unique job identifier.
        **kwargs: Fields to update (status, stage, stage_name, files_total, etc.).

    Returns:
        Updated ScanJob or None if not found.
    """
    job = session.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        return None
    for key, value in kwargs.items():
        if hasattr(job, key):
            setattr(job, key, value)
    session.commit()
    session.refresh(job)
    return job


def get_scan_job(session: Session, job_id: str) -> Optional[ScanJob]:
    """Retrieve a scan job by its job ID.

    Args:
        session: Active SQLAlchemy session.
        job_id: Unique job identifier.

    Returns:
        The matching ScanJob or None if not found.
    """
    return session.query(ScanJob).filter(ScanJob.job_id == job_id).first()


def get_metrics(session: Session) -> dict:
    """Compute aggregate metrics across all stored scans.

    Args:
        session: Active SQLAlchemy session.

    Returns:
        Dict with keys: total_scans, total_vulns, total_cost_usd,
        avg_duration_seconds. Numeric values default to 0 when no scans exist.
    """
    row = session.query(
        func.count(ScanRecord.scan_id).label("total_scans"),
        func.sum(ScanRecord.vuln_count).label("total_vulns"),
        func.sum(ScanRecord.cost_usd).label("total_cost_usd"),
        func.avg(ScanRecord.duration_seconds).label("avg_duration_seconds"),
    ).one()

    return {
        "total_scans": row.total_scans or 0,
        "total_vulns": int(row.total_vulns or 0),
        "total_cost_usd": round(float(row.total_cost_usd or 0.0), 6),
        "avg_duration_seconds": round(float(row.avg_duration_seconds or 0.0), 2),
    }


def create_engine_and_session() -> tuple:
    """Create a SQLAlchemy engine and session factory.

    Uses DATABASE_URL env var if set (Railway PostgreSQL), otherwise
    falls back to SQLite at SWIFT_DB_PATH for local development.

    Returns:
        A two-tuple of (Engine, sessionmaker): the bound SQLAlchemy engine
        and a configured session factory. Call SessionLocal() to obtain a session.

    Raises:
        sqlalchemy.exc.ArgumentError: If DATABASE_URL is set but is not a
            valid SQLAlchemy connection string.
    """
    if _DATABASE_URL and _DATABASE_URL.strip():
        engine = create_engine(_DATABASE_URL)
    else:
        engine = create_engine(
            f"sqlite:///{_DB_PATH}",
            connect_args={"check_same_thread": False},
        )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal
