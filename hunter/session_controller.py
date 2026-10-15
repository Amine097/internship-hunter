"""Session controller: drives accepted sessions through the host broker, runs the scans, and
ALWAYS restores. Runs as its own container, separate from the Telegram bot, so a bot or
Telegram outage cannot strand a session. All state lives in PostgreSQL: a crashed controller
resumes where it left off; the host watchdog is the independent backstop.
"""
import logging
import signal
import threading
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import distinct, func, select, update

from hunter import orchestrator, sessions
from hunter.db import session_scope
from hunter.models import (
    Job,
    ResourceSession,
    RsmCommand,
    Scan,
    ScanJob,
    SearchProfile,
)
from hunter.rsm_client import RsmUnavailable
from hunter.settings import get_settings
from hunter.taskqueue import TaskQueue

log = logging.getLogger("hunter.session_controller")
SCAN_TERMINAL = ("finished", "partial", "failed", "cancelled")
PREPARE_RETRIES = 6            # broker unreachable at prepare: nothing was stopped yet
RESTORE_RETRY_AFTER = timedelta(seconds=20)
RESTORE_MAX_FAST_ATTEMPTS = 5  # then the state becomes restore_failed (still retried slowly)

REASONS = {
    "blocked_busy": "a protected service is busy (e.g. active playback or an Immich job)",
    "blocked_dependency": "an unlisted container depends on a container that would be stopped",
    "session_active": "the host helper already has an active session",
    "busy": "the host helper is busy",
    "stop_failed": "a container could not be stopped",
    "insufficient_memory": "stopping the approved containers did not free enough memory",
    "deadline_passed": "the session deadline had already passed",
}


class SessionController:
    def __init__(self, rsm, queue: TaskQueue | None = None,
                 clock: Callable[[], datetime] = sessions.now):
        self.rsm, self.queue, self.now = rsm, queue or TaskQueue(), clock

    # -- helpers ------------------------------------------------------------------------------
    def _set(self, sid: str, expect: str, **values) -> bool:
        with session_scope() as db:
            return bool(db.execute(update(ResourceSession).where(
                ResourceSession.id == sid, ResourceSession.state == expect,
            ).values(**values)).rowcount)

    def _notify(self, sid: str, text: str, kind: str = "info") -> None:
        with session_scope() as db:
            sessions.notify(db, text, kind=kind, session_id=sid)

    def _finish(self, sid: str, expect: str, final: str, **result) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            merged = {**(row.result or {}), **result}
            won = db.execute(update(ResourceSession).where(
                ResourceSession.id == sid, ResourceSession.state == expect,
            ).values(state=final, lock_key=None, finished_at=self.now(), result=merged,
                     error=merged.get("reason") if final != "completed" else None)).rowcount
            if won:
                log.info("session %s -> %s", sid, final)

    # -- main tick ----------------------------------------------------------------------------
    def tick(self) -> None:
        sessions.expire_pending(self.now())
        self._handle_commands()
        with session_scope() as db:
            row = db.scalar(select(ResourceSession).where(
                ResourceSession.state.in_(sessions.SESSION_ACTIVE)))
            if row is None:
                return
            sid, state = row.id, row.state
        handler = {"accepted": self._accepted, "reserving": self._reserving,
                   "running": self._running, "restoring": self._restoring,
                   "restore_failed": self._restoring}[state]
        handler(sid)

    # -- commands (/restore) --------------------------------------------------------------------
    def _handle_commands(self) -> None:
        with session_scope() as db:
            cmds = list(db.scalars(select(RsmCommand).where(RsmCommand.handled_at.is_(None))))
            ids = [c.id for c in cmds]
        for cid in ids:
            try:
                res = self.rsm.emergency_restore() if self.rsm else {"ok": True,
                                                                   "code": "rsm_disabled"}
            except RsmUnavailable as exc:
                res = {"ok": False, "code": "unavailable", "error": str(exc)}
            with session_scope() as db:
                cmd = db.get(RsmCommand, cid)
                cmd.handled_at, cmd.result = self.now(), res
                text = ("Emergency restore: all approved containers are running again."
                        if res.get("ok") else
                        f"EMERGENCY RESTORE FAILED ({res.get('code')}): "
                        f"{sorted((res.get('failures') or {}))}")
                sessions.notify(db, text, kind="info" if res.get("ok") else "alert")

    # -- accepted -> reserving ------------------------------------------------------------------
    def _accepted(self, sid: str) -> None:
        if self.rsm is None:  # broker not installed: approval still gates, no reservation
            self._notify(sid, "No resource broker is configured on this host: starting "
                              "without reserving resources.")
            self._start_scans(sid, reserved=False)
            return
        self._set(sid, "accepted", state="reserving")

    # -- reserving: prepare + stop -------------------------------------------------------------
    def _reserving(self, sid: str) -> None:
        try:
            prep = self.rsm.prepare(sid)
        except RsmUnavailable as exc:
            return self._reserve_unavailable(sid, str(exc))
        if not prep.get("ok"):
            return self._blocked(sid, prep)             # nothing was stopped
        try:
            stop = self.rsm.stop_approved(sid)
        except RsmUnavailable:
            # outcome unknown: containers may be stopped. Go through restore, never assume.
            self._to_restoring(sid, "reserving", final="blocked",
                               reason="lost contact with the host helper while stopping")
            return
        if not stop.get("ok"):
            self._to_restoring(sid, "reserving", final="blocked",
                               reason=REASONS.get(stop.get("code"), stop.get("code")),
                               broker=stop)
            return
        stopped = stop.get("stopped") or []
        self._notify(sid, f"Resources reserved: stopped {len(stopped)} container(s) "
                          f"({', '.join(stopped) or 'none'}). Starting the research agents.")
        self._start_scans(sid, reserved=True, broker=stop)

    def _reserve_unavailable(self, sid: str, why: str) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            attempts = (row.restore_attempts or 0) + 1
            row.restore_attempts = attempts
        if attempts >= PREPARE_RETRIES:
            self._finish(sid, "reserving", "blocked", reason=f"host helper unreachable ({why})")
            self._notify(sid, "Not started: the host resource helper is unreachable. No "
                              "containers were changed.", kind="alert")

    def _blocked(self, sid: str, prep: dict) -> None:
        detail = REASONS.get(prep.get("code"), prep.get("code"))
        extra = ""
        if prep.get("blockers"):
            extra = " (" + "; ".join(f"{b['container']}: {b['detail']}"
                                     for b in prep["blockers"]) + ")"
        if prep.get("dependents"):
            extra = " (" + "; ".join(f"{d['dependent']} needs {d['depends_on']}"
                                     for d in prep["dependents"]) + ")"
        self._finish(sid, "reserving", "blocked", reason=detail + extra, broker=prep)
        self._notify(sid, f"Not started: {detail}{extra}. No containers were changed.",
                     kind="alert")

    # -- start scans ----------------------------------------------------------------------------
    def _start_scans(self, sid: str, reserved: bool, broker: dict | None = None) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            wanted = row.profile_ids
            if wanted is None:
                wanted = list(db.scalars(select(SearchProfile.id).where(
                    SearchProfile.enabled.is_(True))))
        scan_ids = []
        for pid in wanted:
            try:
                scan_ids.append(orchestrator.enqueue_scan(pid, self.queue))
            except ValueError:
                continue
        deadline = self.now() + timedelta(seconds=get_settings().session_max_seconds)
        with session_scope() as db:
            db.execute(update(ResourceSession).where(
                ResourceSession.id == sid,
                ResourceSession.state.in_(("accepted", "reserving")),
            ).values(state="running", started_at=self.now(), deadline=deadline,
                     scan_ids=scan_ids, broker=broker or {},
                     result={"reserved": reserved}))
        self._notify(sid, f"Research session running: {len(scan_ids)} scan(s) queued "
                          f"(max {get_settings().session_max_seconds // 60} min).")

    # -- running: wait, heartbeat, enforce limits -------------------------------------------------
    def _running(self, sid: str) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            scan_ids, deadline = list(row.scan_ids), row.deadline
            asked = row.restore_requested
            reserved = (row.result or {}).get("reserved", False)
            states = {s: st for s, st in db.execute(
                select(Scan.id, Scan.state).where(Scan.id.in_(scan_ids)))} if scan_ids else {}

        if reserved and self.rsm is not None:
            try:
                st = self.rsm.status(sid)            # also the controller's heartbeat
                with session_scope() as db:
                    db.get(ResourceSession, sid).broker = st.get("session") or {}
                if not st.get("active"):
                    # the watchdog (or an operator) already restored and ended the session
                    self._finish(sid, "running", "failed",
                                 reason="the host watchdog ended the session early")
                    self._notify(sid, "Research session was ended early by the host "
                                      "watchdog; containers were restored.", kind="alert")
                    return
            except RsmUnavailable:
                log.warning("broker status unavailable for %s", sid)

        if asked:
            return self._to_restoring(sid, "running", final="failed",
                                      reason="restore requested by the owner")
        if deadline is not None and self.now().replace(tzinfo=None) >= \
                deadline.replace(tzinfo=None):
            return self._to_restoring(sid, "running", final="failed",
                                      reason="session timed out")
        if scan_ids and all(states.get(s) in SCAN_TERMINAL for s in scan_ids):
            bad = [s for s, st in states.items() if st in ("failed", "cancelled")]
            if bad:
                return self._to_restoring(sid, "running", final="failed",
                                          reason=f"scan(s) failed: {bad}")
            return self._to_restoring(sid, "running", final="completed")
        if not scan_ids:
            return self._to_restoring(sid, "running", final="failed", reason="no scans to run")

    def _to_restoring(self, sid: str, expect: str, final: str, reason: str | None = None,
                      broker: dict | None = None) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            res = {**(row.result or {}), "final": final}
            if reason:
                res["reason"] = reason
            db.execute(update(ResourceSession).where(
                ResourceSession.id == sid, ResourceSession.state == expect,
            ).values(state="restoring", result=res, restore_attempts=0,
                     broker=broker or row.broker or {}))

    # -- restoring (always) -------------------------------------------------------------------
    def _restoring(self, sid: str) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            reserved = (row.result or {}).get("reserved", True)
            state, attempts = row.state, row.restore_attempts or 0
            final = (row.result or {}).get("final", "failed")
            last = row.broker.get("_last_try") if row.broker else None
            if last and state in ("restoring", "restore_failed") and attempts:
                due = datetime.fromisoformat(last) + RESTORE_RETRY_AFTER
                if self.now().replace(tzinfo=None) < due.replace(tzinfo=None):
                    return
        # stop whatever scans are still pending: the session is over
        with session_scope() as db:
            scan_ids = list(db.get(ResourceSession, sid).scan_ids or [])
        for scan_id in scan_ids:
            self.queue.cancel(scan_id)

        ok, detail = True, {}
        if self.rsm is not None and reserved is not False:
            try:
                res = self.rsm.restore(sid)
                ok, detail = bool(res.get("ok")), res
            except RsmUnavailable as exc:
                ok, detail = False, {"code": "unavailable", "failures": {"broker": str(exc)}}

        if ok:
            self._notify_completion(sid, final)
            self._finish(sid, state, final)
            return
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            row.restore_attempts = attempts + 1
            row.broker = {**(row.broker or {}), "_last_try": self.now().isoformat(),
                          "restore": detail}
            first = attempts == 0
            if attempts + 1 >= RESTORE_MAX_FAST_ATTEMPTS and row.state == "restoring":
                row.state = "restore_failed"
        if first:
            names = sorted((detail.get("failures") or {}).keys()) or detail.get("code")
            self._notify(sid, f"RESTORATION FAILED: some containers are still stopped ({names})."
                              " Retrying automatically; the host watchdog is also retrying. "
                              "Use /restore to force it.", kind="alert")

    def _notify_completion(self, sid: str, final: str) -> None:
        with session_scope() as db:
            row = db.get(ResourceSession, sid)
            ids = list(row.scan_ids or [])
            reason = (row.result or {}).get("reason")
            reserved = (row.result or {}).get("reserved", False)
            scans = list(db.execute(select(Scan.id, Scan.state, Scan.discovered)
                                    .where(Scan.id.in_(ids)))) if ids else []
            new_jobs = db.scalar(
                select(func.count(distinct(Job.id))).select_from(Job)
                .join(ScanJob, ScanJob.job_id == Job.id).where(ScanJob.scan_id.in_(ids))
            ) if ids else 0
        summary = ", ".join(f"#{i}:{st}" for i, st, _ in scans) or "no scans"
        restored = "All containers restored." if reserved else "No containers were changed."
        head = {"completed": "Research session finished.",
                "failed": f"Research session ended with problems ({reason}).",
                "blocked": f"Research session did not run ({reason})."}.get(final, final)
        self._notify(sid, f"{head} Scans: {summary}. Jobs seen: {new_jobs}. {restored}",
                     kind="info" if final == "completed" else "alert")


def main() -> None:  # pragma: no cover - process entry point
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    from hunter.rsm_client import RsmClient
    rsm = RsmClient(s.rsm_socket) if s.rsm_enabled else None
    controller = SessionController(rsm)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    log.info("session controller started (rsm_enabled=%s)", s.rsm_enabled)
    while not stop.is_set():
        try:
            controller.tick()
        except Exception:
            log.exception("controller tick failed")
        stop.wait(3.0)


if __name__ == "__main__":
    main()
