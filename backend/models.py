"""SQLAlchemy models for the XSS Hunter."""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Text, DateTime, ForeignKey, Boolean, JSON, Index
)
from sqlalchemy.orm import relationship
import uuid

from db import Base


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_now)


class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    allowed_domains = Column(JSON, default=list)     # ["example.com", "*.foo.com"]
    excluded_paths = Column(JSON, default=list)      # ["/logout", "/admin"]
    created_at = Column(DateTime, default=_now)
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=_uuid)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="QUEUED", index=True)  # QUEUED/RUNNING/PAUSED/STOPPING/STOPPED/COMPLETED/FAILED
    config = Column(JSON, default=dict)                    # depth, concurrency, rate limit
    stats = Column(JSON, default=dict)                     # urls_crawled, params_tested, candidates, findings
    error = Column(Text, default="")
    created_at = Column(DateTime, default=_now)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    urls = relationship("DiscoveredURL", back_populates="scan", cascade="all, delete-orphan")


class DiscoveredURL(Base):
    __tablename__ = "discovered_urls"
    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    method = Column(String, default="GET")
    params = Column(JSON, default=list)
    depth = Column(Integer, default=0)
    tested = Column(Boolean, default=False)
    scan = relationship("Scan", back_populates="urls")


class Candidate(Base):
    """A candidate is a parameter reflection prior to browser validation."""
    __tablename__ = "candidates"
    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    method = Column(String, default="GET")
    param = Column(String, nullable=False)
    context = Column(String, default="unknown")  # html/attribute/javascript/encoded/none
    reflected_raw = Column(Boolean, default=False)
    payload_marker = Column(String, default="")
    validated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    method = Column(String, default="GET")
    param = Column(String, nullable=False)
    context = Column(String, default="unknown")
    classification = Column(String, default="potential")  # reflection_only/safely_encoded/potential/validated/false_positive
    severity = Column(String, default="medium")           # low/medium/high/critical
    payload = Column(Text, default="")
    evidence = Column(Text, default="")
    request_dump = Column(Text, default="")
    response_snippet = Column(Text, default="")
    validated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)
    scan = relationship("Scan", back_populates="findings")


Index("ix_findings_scan_class", Finding.scan_id, Finding.classification)
