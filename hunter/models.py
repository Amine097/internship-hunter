from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SearchProfile(Base):
    __tablename__ = "search_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    filters: Mapped[dict] = mapped_column(JSON)


ACTIVE_STATES = ("queued", "running")
SCAN_STATES = ("queued", "running", "finished", "partial", "failed", "cancelled")
TASK_STATES = ("queued", "running", "completed", "failed", "cancelled")
TASK_KINDS = ("scan",)  # a closed set: there is no dynamic dispatch anywhere


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(_in("state", SCAN_STATES), name="ck_scans_state"),
        # At most one active scan per profile: concurrent /scan calls cannot pile up.
        Index(
            "uq_scans_one_active_per_profile", "profile_id", unique=True,
            postgresql_where=text("state IN ('queued', 'running')"),
            sqlite_where=text("state IN ('queued', 'running')"),
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("search_profiles.id"))
    state: Mapped[str] = mapped_column(String(30), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    agent_reports: Mapped[list] = mapped_column(JSON, default=list)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    canonical_key: Mapped[str] = mapped_column(String(280), unique=True)
    source: Mapped[str] = mapped_column(String(40))
    source_url: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(350))
    company: Mapped[str] = mapped_column(String(200))
    location: Mapped[str] = mapped_column(String(250), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (UniqueConstraint("scan_id", "job_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    decision: Mapped[str] = mapped_column(String(30), default="unassessed")
    reason: Mapped[str] = mapped_column(Text, default="")


class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    agent: Mapped[str] = mapped_column(String(30))
    state: Mapped[str] = mapped_column(String(30))
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), unique=True)
    state: Mapped[str] = mapped_column(String(30), default="not_started")
    # Deliberate: V1 provides no code path to actually submit applications.


class Task(Base):
    """The work queue. One row per scan; claimed with SELECT ... FOR UPDATE SKIP LOCKED.

    There is no payload and no function name: ``kind`` is a CHECK-constrained enum and the
    only argument is the foreign key ``scan_id``. A worker acts on a task only while it holds
    the unexpired ``lease_token``.
    """
    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint(_in("kind", TASK_KINDS), name="ck_tasks_kind"),
        CheckConstraint(_in("state", TASK_STATES), name="ck_tasks_state"),
        CheckConstraint("attempts >= 0 AND max_attempts >= 1", name="ck_tasks_attempts"),
        Index("ix_tasks_claim", "state", "available_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), default="scan")
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True)
    state: Mapped[str] = mapped_column(String(20), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
