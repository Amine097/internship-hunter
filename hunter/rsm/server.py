"""Unix-socket front end. The wire protocol is deliberately tiny:

    {"op": "<one of 5>", "session_id": "<uuid-ish>"}\\n   ->   {"ok": bool, "code": str, ...}\\n

No other key is accepted; there is no field through which a container name, command, path
or option could be supplied."""
import json
import os
import socket
import socketserver
import struct

from hunter.rsm import OPERATIONS
from hunter.rsm.broker import Broker
from hunter.rsm.policy import SESSION_ID

MAX_REQUEST_BYTES = 512


def handle_request(broker: Broker, raw: bytes) -> dict:
    """Pure request -> response mapping (also used by in-process tests)."""
    if len(raw) > MAX_REQUEST_BYTES:
        return {"ok": False, "code": "bad_request"}
    try:
        req = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "code": "bad_request"}
    if not isinstance(req, dict) or set(req) - {"op", "session_id"}:
        return {"ok": False, "code": "bad_request"}
    op, sid = req.get("op"), req.get("session_id")
    if op not in OPERATIONS:
        return {"ok": False, "code": "unknown_operation"}
    needs_id = op in ("prepare", "stop_approved", "restore")
    if needs_id and not (isinstance(sid, str) and SESSION_ID.match(sid)):
        return {"ok": False, "code": "bad_session_id"}
    if op in ("emergency_restore",) and sid is not None:
        return {"ok": False, "code": "bad_request"}
    if op == "status" and sid is not None and not (isinstance(sid, str)
                                                    and SESSION_ID.match(sid)):
        return {"ok": False, "code": "bad_session_id"}
    try:
        if op == "prepare":
            return broker.prepare(sid)
        if op == "stop_approved":
            return broker.stop_approved(sid)
        if op == "restore":
            return broker.restore(sid)
        if op == "status":
            return broker.status(sid)
        return broker.emergency_restore()
    except Exception as exc:  # never leak internals over the socket
        broker.store.audit("operation_error", op=op, error=type(exc).__name__)
        return {"ok": False, "code": "internal_error"}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        uid = struct.unpack("3i", self.request.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
        if self.server.allowed_uids and uid not in self.server.allowed_uids:
            self.server.broker.store.audit("peer_rejected", uid=uid)
            self.wfile.write(b'{"ok": false, "code": "forbidden"}\n')
            return
        raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        resp = handle_request(self.server.broker, raw)
        self.wfile.write(json.dumps(resp).encode() + b"\n")


class RsmServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, path: str, broker: Broker, group: str | None, allowed_uids=()):
        self.broker, self.allowed_uids = broker, tuple(allowed_uids)
        if os.path.exists(path):
            os.unlink(path)
        super().__init__(path, _Handler)
        os.chmod(path, 0o660)
        if group:
            import grp
            os.chown(path, -1, grp.getgrnam(group).gr_gid)
