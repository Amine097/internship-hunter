"""Approval state machine for resource sessions (database side, no Docker, no broker).

pending --accept--> accepted --> reserving --> running --> restoring --> completed|failed|blocked
   |                                                         ^
   +--decline--> declined      (no response) --> expired     +-- restore_failed (retries)

Every transition is a conditional UPDATE (compare-and-set), so repeated Telegram callbacks,
concurrent controllers and replays cannot double-apply anything.
"""
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from hunter.db import session_scope
from hunter.models import (
    SESSION_ACTIVE,
    Notification,
    ResourceSession,
    RsmCommand,
)
from hunter.settings import get_settings


def now() -> datetime:
    return datetime.now(timezone.utc)


def notify(db, text: str, kind: str = "info", session_id: str | None = None) -> None:
    db.add(Notification(kind=kind, text=text[:3500], session_id=session_id))


# -- requesting ------------------------------------------------------------------------------

def request_session(trigger: str, profile_ids: list[int] | None = None,
                    slot_key: str | None = None, at: datetime | None = None,
                    ttl_seconds: int | None = None) -> tuple[str, bool]:
    """Creates a PENDING approval request. Returns (session_id, created).

    Nothing is started or stopped here; this only asks the owner. A repeated ``slot_key``
    (scheduler restart, duplicate cron fire) returns the existing request.
    """
    at = at or now()
    ttl = ttl_seconds or get_settings().approval_ttl_seconds
    sid = str(uuid.uuid4())
    try:
        with session_scope() as db:
            db.add(ResourceSession(
                id=sid, trigger=trigger, slot_key=slot_key, profile_ids=profile_ids,
                state="pending", nonce=secrets.token_hex(8), created_at=at,
                expires_at=at + timedelta(seconds=ttl), scan_ids=[], broker={}, result={},
                restore_attempts=0, restore_requested=False,
            ))
        return sid, True
    except IntegrityError:
        with session_scope() as db:
            existing = db.scalar(select(ResourceSession.id).where(
                ResourceSession.slot_key == slot_key))
        if existing is None:
            raise
        return existing, False


# -- deciding (called by the Telegram bot after authenticating the owner) --------------------

@dataclass(frozen=True)
class Decision:
    outcome: str      # accepted|declined|expired|already_handled|busy|unknown|bad_nonce
    session_id: str | None = None


def decide(session_id: str, nonce: str, accept: bool, at: datetime | None = None) -> Decision:
    at = at or now()
    with session_scope() as db:
        row = db.get(ResourceSession, session_id)
        if row is None:
            return Decision("unknown")
        if not secrets.compare_digest(row.nonce, nonce or ""):
            return Decision("bad_nonce", session_id)
        state, expires = row.state, row.expires_at
    if state != "pending":
        return Decision("already_handled", session_id)
    if expires.replace(tzinfo=timezone.utc) <= at:
        expire_pending(at)
        return Decision("expired", session_id)

    if not accept:
        with session_scope() as db:
            won = db.execute(update(ResourceSession).where(
                ResourceSession.id == session_id, ResourceSession.state == "pending",
            ).values(state="declined", decided_at=at, finished_at=at)).rowcount
            if won:
                notify(db, "Research session declined. No containers were changed.",
                       session_id=session_id)
        return Decision("declined" if won else "already_handled", session_id)

    try:
        with session_scope() as db:
            won = db.execute(update(ResourceSession).where(
                ResourceSession.id == session_id, ResourceSession.state == "pending",
                ResourceSession.nonce == nonce, ResourceSession.expires_at > at,
            ).values(state="accepted", lock_key="active", decided_at=at)).rowcount
            if not won:
                return Decision("already_handled", session_id)
            notify(db, "Approved. Reserving server resources...", session_id=session_id)
        return Decision("accepted", session_id)
    except IntegrityError:
        # another session is active: the unique lock_key refused this one
        with session_scope() as db:
            db.execute(update(ResourceSession).where(
                ResourceSession.id == session_id, ResourceSession.state == "pending",
            ).values(state="blocked", decided_at=at, finished_at=at, lock_key=None,
                     error="another research session is already active"))
            notify(db, "Not started: another research session is already active.",
                   kind="alert", session_id=session_id)
        return Decision("busy", session_id)


def expire_pending(at: datetime | None = None) -> list[str]:
    """Unanswered requests expire; they are never auto-launched."""
    at = at or now()
    with session_scope() as db:
        ids = list(db.scalars(select(ResourceSession.id).where(
            ResourceSession.state == "pending", ResourceSession.expires_at <= at)))
        out = []
        for sid in ids:
            won = db.execute(update(ResourceSession).where(
                ResourceSession.id == sid, ResourceSession.state == "pending",
            ).values(state="expired", finished_at=at)).rowcount
            if won:
                out.append(sid)
                notify(db, "Research session request expired without an answer; nothing "
                           "was started.", session_id=sid)
        return out


# -- owner commands --------------------------------------------------------------------------

def request_emergency_restore() -> int:
    with session_scope() as db:
        cmd = RsmCommand(command="emergency_restore", result={})
        db.add(cmd)
        db.flush()
        for row in db.scalars(select(ResourceSession).where(
                ResourceSession.state.in_(SESSION_ACTIVE))):
            row.restore_requested = True
        return cmd.id


def active_session_id() -> str | None:
    with session_scope() as db:
        return db.scalar(select(ResourceSession.id).where(
            ResourceSession.state.in_(SESSION_ACTIVE)))
