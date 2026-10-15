"""Application-side client for the host broker (Unix socket, one JSON line each way).

Only the session controller uses this. It speaks the five operations and nothing else; the
broker, not this client, is the security boundary."""
import json
import socket


class RsmUnavailable(RuntimeError):
    """Broker unreachable or answered nonsense. Callers must treat this as 'state unknown'."""


class RsmClient:
    def __init__(self, path: str, timeout: float = 400.0):
        self.path, self.timeout = path, timeout

    def _call(self, payload: dict) -> dict:
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
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
