"""Durable session state + append-only audit log. Survives crashes and reboots.

RECOVERY STATE IS NEVER SILENTLY DISCARDED. A corrupt or unreadable ``session.json`` raises
``StateCorrupt`` on every access (the file stays exactly where it is); callers report it
loudly and never fall back to "idle", because "idle" could leave production containers
stopped. Every good write also refreshes ``session.json.bak`` so an administrator can see
and recover the last known-good snapshot (``python -m hunter.rsm admin ...``).
"""
import contextlib
import fcntl
import json
import os
import time
from pathlib import Path


class StateCorrupt(RuntimeError):
    """The recovery state exists but cannot be trusted. Requires administrator action."""


EMPTY = {"version": 1, "session": None, "history": []}


class Store:
    def __init__(self, directory: str | Path, clock=time.time):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.state_path = self.dir / "session.json"
        self.backup_path = self.dir / "session.json.bak"
        self.audit_path = self.dir / "audit.log"
        self.lock_path = self.dir / "lock"
        self.alert_path = self.dir / "alerts.json"
        self.clock = clock

    # -- locking: one operation at a time, across processes (server, watchdog, recover) ----
    @contextlib.contextmanager
    def lock(self, blocking: bool = True):
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o640)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                yield False
                return
            yield True
        finally:
            os.close(fd)  # closing releases the flock, also if the process is SIGKILLed

    # -- state ------------------------------------------------------------------------------
    @staticmethod
    def _validate(doc) -> dict:
        if not isinstance(doc, dict) or doc.get("version") != 1 or "session" not in doc:
            raise ValueError("unexpected structure")
        s = doc["session"]
        if s is not None:
            for key in ("id", "phase", "deadline", "last_contact", "snapshot", "stop_order",
                        "stopped", "failures"):
                if key not in s:
                    raise ValueError(f"session lacks {key!r}")
        doc.setdefault("history", [])
        return doc

    def load(self) -> dict:
        try:
            raw = self.state_path.read_text()
        except FileNotFoundError:
            return json.loads(json.dumps(EMPTY))
        except OSError as exc:
            raise StateCorrupt(f"cannot read {self.state_path}: {exc}") from exc
        try:
            return self._validate(json.loads(raw))
        except ValueError as exc:
            self.audit("state_corrupt", path=str(self.state_path), error=str(exc)[:120])
            raise StateCorrupt(
                f"{self.state_path} is corrupt ({exc}). It was left untouched. Inspect it and "
                f"{self.backup_path}, then use `python -m hunter.rsm admin` to recover."
            ) from exc

    def save(self, state: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        # keep the previous good version for administrator recovery
        if self.state_path.exists():
            try:
                self._validate(json.loads(self.state_path.read_text()))
                os.replace(self.state_path, self.backup_path)
            except (ValueError, OSError):
                pass  # never overwrite a good backup with a bad file
        os.replace(tmp, self.state_path)
        dfd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def load_backup(self) -> dict | None:
        try:
            return self._validate(json.loads(self.backup_path.read_text()))
        except (OSError, ValueError):
            return None

    # -- alert rate limiting (host-side notifications) --------------------------------------
    def alert_due(self, key: str, min_interval: float) -> bool:
        try:
            last = json.loads(self.alert_path.read_text()).get(key, 0)
        except (OSError, ValueError):
            last = 0
        now = self.clock()
        if now - last < min_interval:
            return False
        try:
            doc = json.loads(self.alert_path.read_text())
        except (OSError, ValueError):
            doc = {}
        doc[key] = now
        self.alert_path.write_text(json.dumps(doc))
        return True

    # -- audit ------------------------------------------------------------------------------
    def audit(self, event: str, **fields) -> None:
        line = json.dumps({"ts": round(self.clock(), 3), "event": event, **fields},
                          sort_keys=True, default=str)
        fd = os.open(self.audit_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o640)
        try:
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def audit_events(self) -> list[dict]:
        try:
            return [json.loads(ln) for ln in self.audit_path.read_text().splitlines() if ln]
        except FileNotFoundError:
            return []
