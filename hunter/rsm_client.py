"""Application-side client for the host broker (Unix socket, one JSON line each way).

Only the session controller uses this. It speaks the five operations and nothing else; the
broker, not this client, is the security boundary."""
import json
import socket
import time


class RsmUnavailable(RuntimeError):
    """Broker unreachable or answered nonsense. Callers must treat this as 'state unknown'."""


CONNECT_RETRIES = 3          # broker restarting: connection refused / socket briefly absent
CONNECT_RETRY_DELAY = 1.0
TIMEOUT_MARGIN = 120.0       # client deadline = broker's worst-case stop phase + this


class RsmClient:
    def __init__(self, path: str, timeout: float = 400.0):
        self.path, self.timeout = path, timeout

    def ensure_timeout(self, limits: dict | None) -> None:
        """The read deadline must exceed the broker's bounded worst case, or a slow but
        healthy shutdown would be reported as 'lost contact'. Uses the budget the broker
        itself advertises (policy-derived), never a guess."""
        budget = (limits or {}).get("stop_phase_budget_seconds")
        if isinstance(budget, int | float):
            self.timeout = max(self.timeout, float(budget) + TIMEOUT_MARGIN)

    def _connect(self) -> socket.socket:
        last: OSError | None = None
        for attempt in range(CONNECT_RETRIES):
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(self.timeout)
            try:
                s.connect(self.path)       # only CONNECT is retried; never a half-done request
                return s
            except (ConnectionRefusedError, FileNotFoundError) as exc:
                s.close()
                last = exc
                if attempt + 1 < CONNECT_RETRIES:
                    time.sleep(CONNECT_RETRY_DELAY)
            except OSError:
                s.close()
                raise
        raise last or OSError("connect failed")

    def _call(self, payload: dict) -> dict:
        try:
            with self._connect() as s:
                s.sendall(json.dumps(payload).encode() + b"\n")
                line = s.makefile("rb").readline(65536)
            resp = json.loads(line)
        except (OSError, ValueError) as exc:
            raise RsmUnavailable(type(exc).__name__) from exc
        if not isinstance(resp, dict) or "ok" not in resp:
            raise RsmUnavailable("malformed response")
        return resp

    def prepare(self, session_id: str) -> dict:
        return self._call({"op": "prepare", "session_id": session_id})

    def stop_approved(self, session_id: str) -> dict:
        return self._call({"op": "stop_approved", "session_id": session_id})

    def restore(self, session_id: str) -> dict:
        return self._call({"op": "restore", "session_id": session_id})

    def status(self, session_id: str | None = None) -> dict:
        return self._call({"op": "status", **({"session_id": session_id} if session_id else {})})

    def emergency_restore(self) -> dict:
        return self._call({"op": "emergency_restore"})
