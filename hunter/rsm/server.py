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


SD_LISTEN_FDS_START = 3


class RsmServer(socketserver.UnixStreamServer):
    """Production: the listening socket is created, owned (SocketUser/SocketGroup) and
    permissioned (SocketMode) by systemd and inherited here, so this process needs no
    capability to chown/chmod anything and keeps a locked-down sandbox. The standalone
    ``path`` mode exists for development and tests only."""

    allow_reuse_address = True

    def __init__(self, path: str | None, broker: Broker, allowed_uids=(),
                 sock: socket.socket | None = None):
        self.broker, self.allowed_uids = broker, tuple(allowed_uids)
        if sock is not None:
            super().__init__(sock.getsockname(), _Handler, bind_and_activate=False)
            self.socket.close()
            self.socket = sock                  # already bound + listening (by systemd)
            return
        if os.path.exists(path):
            os.unlink(path)
        old = os.umask(0o117)                   # socket is created 0660: no chmod needed
        try:
            super().__init__(path, _Handler)
        finally:
            os.umask(old)

    @classmethod
    def from_systemd(cls, broker: Broker, allowed_uids=()) -> "RsmServer":
        """Adopt the socket passed via the sd_listen_fds protocol (fd 3)."""
        if os.environ.get("LISTEN_PID") != str(os.getpid()):
            raise RuntimeError("not socket-activated (LISTEN_PID does not match)")
        if int(os.environ.get("LISTEN_FDS", "0")) < 1:
            raise RuntimeError("not socket-activated (LISTEN_FDS < 1)")
        for var in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            os.environ.pop(var, None)
        sock = socket.socket(fileno=SD_LISTEN_FDS_START)
        if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
            raise RuntimeError("inherited descriptor is not an AF_UNIX stream socket")
        return cls(None, broker, allowed_uids, sock=sock)
