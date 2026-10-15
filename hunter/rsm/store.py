"""Durable session state + append-only audit log. Survives crashes and reboots."""
import contextlib
import fcntl
import json
import os
import time
from pathlib import Path


class Store:
    def __init__(self, directory: str | Path, clock=time.time):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.state_path = self.dir / "session.json"
        self.audit_path = self.dir / "audit.log"
        self.lock_path = self.dir / "lock"
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
    def load(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return {"version": 1, "session": None, "history": []}
        except json.JSONDecodeError:
            # never silently drop a possibly-active session: keep the evidence, fail loudly
            bad = self.state_path.with_suffix(f".corrupt-{int(self.clock())}")
            os.replace(self.state_path, bad)
            self.audit("state_corrupt", moved_to=str(bad))
            raise RuntimeError(f"session state was corrupt; preserved as {bad}") from None

    def save(self, state: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)
        dfd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

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
