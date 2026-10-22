#!/usr/bin/python3 -IB
"""Allow-listing CONNECT proxy for ONE agent (stdlib only; docs/security-architecture.md, "Egress").

What a client may do, and what this process checks before a single byte reaches the provider:

  request   exactly `CONNECT <host>:443 HTTP/1.x`; <host> is a name from EGRESS_ALLOW, compared
            exactly (lower-case ASCII). IP literals, other ports, other methods (plain-HTTP
            forwarding included), malformed or oversized requests: 403/400 with X-Egress-Reason.
  resolve   the proxy resolves <host> itself (IPv4 only: there is no IPv6 route) and refuses the
            request if ANY address is not a global unicast address (DNS rebinding to the host,
            the LAN, the tailnet, metadata...). It then connects to the address it validated: the
            check and the use cannot diverge.
  TLS       after `200` the tunnel is gated on the TLS handshake, which is plaintext up to the
            ServerHello: every ClientHello the client sends (the first one and, after a
            HelloRetryRequest, the second) must carry exactly one SNI host_name equal to <host>,
            and no Encrypted Client Hello. Anything that is not a TLS handshake, a ClientHello
            after the ServerHello, a third ClientHello, a malformed handshake: connection cut,
            nothing more forwarded. Once the server's real ServerHello has passed, the tunnel is
            spliced untouched (end-to-end TLS is never terminated or re-signed).

What it CANNOT see (encrypted after the handshake): the HTTP Host / :authority inside TLS. A
CDN that routes by Host rather than SNI ("domain fronting") is out of reach of any proxy that does
not terminate TLS; see the documentation for the boundary and the compensating controls.

Configuration (environment): EGRESS_ALLOW (required, comma-separated exact hostnames),
EGRESS_LISTEN (default 0.0.0.0:3128), EGRESS_MAX_CLIENTS (default 16).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time

# ---- limits --------------------------------------------------------------------------------------
MAX_HEAD = 8192             # CONNECT request head, bytes
MAX_HEADERS = 64
HEAD_TIMEOUT = 10.0         # seconds to send the CONNECT request
RESOLVE_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
HELLO_TIMEOUT = 15.0        # seconds after `200` until the first ClientHello is complete
HANDSHAKE_TIMEOUT = 60.0    # until the server's real ServerHello
IDLE_TIMEOUT = 600.0        # a spliced tunnel with no traffic in either direction
INSPECT_BUDGET_C2S = 1 << 20    # ClientHello(s) + TLS 1.3 early data before the ServerHello
INSPECT_BUDGET_S2C = 1 << 18
MAX_RECORD = 16384 + 2048   # TLSCiphertext upper bound
MAX_HANDSHAKE_MSG = 1 << 16
READ = 65536

# ---- TLS constants -------------------------------------------------------------------------------
CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA = 20, 21, 22, 23
HS_CLIENT_HELLO, HS_SERVER_HELLO = 1, 2
EXT_SERVER_NAME = 0x0000
EXT_ECH = 0xFE0D            # Encrypted Client Hello (draft/RFC 9849)
EXT_ESNI = 0xFFCE           # the older encrypted SNI draft
# RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello whose random is SHA-256("HelloRetryRequest")
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class Silent(Exception):
    """A connection that closed without sending a byte (the healthcheck's `nc -z`): not logged."""


class Refused(Exception):
    """A policy decision. Before `200` it becomes an HTTP error; after, the tunnel is cut."""

    def __init__(self, reason: str, status: int = 403, detail: str = ""):
        super().__init__(reason)
        self.reason, self.status, self.detail = reason, status, detail


# ---- names and addresses -------------------------------------------------------------------------
def valid_hostname(name: str) -> bool:
    """A lower-case ASCII DNS name with at least two labels whose last label is not numeric
    (so no IPv4 literal, no single-label or local name, no IDN/Unicode, no trailing dot)."""
    if not name or len(name) > 253 or not name.isascii():
        return False
    labels = name.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    return all(_LABEL.match(label) for label in labels)


def parse_allowlist(raw: str) -> frozenset[str]:
    names = [n.strip().lower() for n in raw.split(",") if n.strip()]
    if not names:
        raise ValueError("EGRESS_ALLOW is empty")
    for n in names:
        if not valid_hostname(n):
            raise ValueError(f"invalid hostname in EGRESS_ALLOW: {n!r}")
    return frozenset(names)


def address_allowed(addr: str) -> bool:
    """Only global unicast IPv4: never the host, the LAN, the tailnet (100.64/10), link-local,
    loopback, multicast, reserved or documentation space."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global and not ip.is_multicast


# ---- TLS handshake parsing -----------------------------------------------------------------------
class TLSViolation(Refused):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason, 0, detail)


class _Reader:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.p + n > len(self.d):
            raise TLSViolation("tls-malformed", "truncated")
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def vec(self, width: int) -> bytes:
        return self.take(self.u8() if width == 1 else self.u16())

    def done(self) -> bool:
        return self.p == len(self.d)


def parse_client_hello(body: bytes) -> dict:
    """Returns {"sni": str | None, "ech": bool, "alpn": [str]}. Strict: any length that does not
    add up, a duplicated extension or a server_name list that is not exactly one host_name is a
    violation (a parser that guesses is a parser that can be confused)."""
    r = _Reader(body)
    r.take(2)                              # legacy_version
    r.take(32)                             # random
    if len(r.vec(1)) > 32:
        raise TLSViolation("tls-malformed", "session_id")
    suites = r.vec(2)
    if not suites or len(suites) % 2:
        raise TLSViolation("tls-malformed", "cipher_suites")
    if not r.vec(1):
        raise TLSViolation("tls-malformed", "compression_methods")
    out = {"sni": None, "ech": False, "alpn": []}
    if r.done():
        return out                         # no extensions at all: no SNI
    exts = _Reader(r.vec(2))
    if not r.done():
        raise TLSViolation("tls-malformed", "trailing bytes after extensions")
    seen = set()
    while not exts.done():
        etype, data = exts.u16(), exts.vec(2)
        if etype in seen:
            raise TLSViolation("tls-malformed", f"duplicate extension {etype}")
        seen.add(etype)
        if etype == EXT_SERVER_NAME:
            out["sni"] = _parse_server_name(data)
        elif etype in (EXT_ECH, EXT_ESNI):
            out["ech"] = True
        elif etype == 16:                  # ALPN, for the record only
            try:
                lst = _Reader(_Reader(data).vec(2))
                while not lst.done():
                    out["alpn"].append(lst.vec(1).decode("ascii", "replace"))
            except TLSViolation:
                raise TLSViolation("tls-malformed", "alpn") from None
    return out


def _parse_server_name(data: bytes) -> str:
    r = _Reader(data)
    lst = _Reader(r.vec(2))
    if not r.done():
        raise TLSViolation("tls-malformed", "server_name length")
    names = []
    while not lst.done():
        kind, name = lst.u8(), lst.vec(2)
        names.append((kind, name))
    if len(names) != 1 or names[0][0] != 0:
        raise TLSViolation("tls-sni-list", "server_name must hold exactly one host_name")
    try:
        name = names[0][1].decode("ascii")
    except UnicodeDecodeError:
        raise TLSViolation("tls-sni-invalid", "non-ASCII server name") from None
    return name


def is_hello_retry(body: bytes) -> bool:
    r = _Reader(body)
    r.take(2)
    return r.take(32) == HRR_RANDOM


class RecordStream:
    """Splits one direction of a TLS connection into records and plaintext handshake messages."""

    def __init__(self):
        self.buf = bytearray()
        self.hs = bytearray()

    def feed(self, data: bytes) -> None:
        self.buf += data

    def next_record(self):
        if len(self.buf) < 5:
            return None
        ctype, major, length = self.buf[0], self.buf[1], int.from_bytes(self.buf[3:5], "big")
        if major != 3 or ctype not in (CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA, 24):
            raise TLSViolation("tls-not-tls", f"record type {ctype} version major {major}")
        if length > MAX_RECORD:
            raise TLSViolation("tls-malformed", "record too large")
        if len(self.buf) < 5 + length:
            return None
        raw = bytes(self.buf[:5 + length])
        del self.buf[:5 + length]
        return ctype, raw, raw[5:]

    def handshake_messages(self, payload: bytes) -> list[tuple[int, bytes]]:
        self.hs += payload
        msgs = []
        while len(self.hs) >= 4:
            mtype, length = self.hs[0], int.from_bytes(self.hs[1:4], "big")
            if length > MAX_HANDSHAKE_MSG:
                raise TLSViolation("tls-malformed", "handshake message too large")
            if len(self.hs) < 4 + length:
                break
            msgs.append((mtype, bytes(self.hs[4:4 + length])))
            del self.hs[:4 + length]
        return msgs

    def take_rest(self) -> bytes:
        rest = bytes(self.buf)
        self.buf.clear()
        return rest


# ---- the tunnel ----------------------------------------------------------------------------------
class Tunnel:
    """Gated splice: both directions are inspected as TLS records until the server's real
    ServerHello has gone through; after that, bytes are copied untouched."""

    def __init__(self, host, creader, cwriter, ureader, uwriter):
        self.host = host
        self.cr, self.cw, self.ur, self.uw = creader, cwriter, ureader, uwriter
        self.client_hellos = 0
        self.retries = 0
        self.server_hello = asyncio.Event()
        self.sni = None
        self.alpn = []
        self.up = self.down = 0
        self.last = time.monotonic()

    async def run(self, early: bytes) -> None:
        """Both directions run until both reached EOF; the first error (a violation, a timeout,
        a reset) cancels the other direction and is re-raised."""
        tasks = [asyncio.create_task(self._client_to_server(early)),
                 asyncio.create_task(self._server_to_client())]
        try:
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if t.exception() is not None:
                        raise t.exception()
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _read(self, reader, timeout):
        data = await asyncio.wait_for(reader.read(READ), timeout)
        self.last = time.monotonic()
        return data

    async def _send(self, writer, data, up):
        writer.write(data)
        await writer.drain()
        if up:
            self.up += len(data)
        else:
            self.down += len(data)

    def _check_client_hello(self, body: bytes) -> None:
        hello = parse_client_hello(body)
        if hello["ech"]:
            raise TLSViolation("tls-ech", "Encrypted Client Hello hides the real server name")
        if hello["sni"] is None:
            raise TLSViolation("tls-no-sni", "ClientHello without server_name")
        if hello["sni"].lower() != self.host:
            raise TLSViolation("tls-sni-mismatch", f"sni={hello['sni'][:253]!r}")
        self.client_hellos += 1
        if self.client_hellos > 1 + self.retries:
            raise TLSViolation("tls-extra-client-hello", "ClientHello without HelloRetryRequest")
        self.sni, self.alpn = hello["sni"].lower(), hello["alpn"]

    async def _client_to_server(self, early: bytes) -> None:
        stream, seen, raw = RecordStream(), 0, False
        if early:
            stream.feed(early)
            seen += len(early)
        while not raw:
            rec = stream.next_record()
            if rec is None:
                timeout = HELLO_TIMEOUT if self.client_hellos == 0 else HANDSHAKE_TIMEOUT
                data = await self._read(self.cr, timeout)
                if not data:
                    self._eof(self.uw)     # an unfinished record is dropped, never forwarded
                    return
                seen += len(data)
                if seen > INSPECT_BUDGET_C2S:
                    raise TLSViolation("tls-inspect-budget", "too much data before the ServerHello")
                stream.feed(data)
                continue
            ctype, record, payload = rec
            done_sh = self.server_hello.is_set()
            if self.client_hellos == 0 and ctype != CT_HANDSHAKE:
                raise TLSViolation("tls-not-handshake", f"first record type {ctype}")
            if ctype == CT_HANDSHAKE:
                for mtype, body in stream.handshake_messages(payload):
                    if mtype == HS_CLIENT_HELLO:
                        if done_sh:
                            raise TLSViolation("tls-client-hello-after-server-hello")
                        self._check_client_hello(body)
                    elif not done_sh:
                        raise TLSViolation("tls-unexpected-handshake", f"message {mtype}")
            elif ctype in (CT_CCS, CT_APPDATA):
                # before the ServerHello: TLS 1.3 compatibility CCS or 0-RTT early data (both
                # opaque, both need a checked ClientHello first); after it: the encrypted part
                if done_sh:
                    raw = True
            elif ctype != CT_ALERT:
                raise TLSViolation("tls-record-type", f"record type {ctype}")
            await self._send(self.uw, record, True)
        rest = stream.take_rest()
        if rest:
            await self._send(self.uw, rest, True)
        await self._pump(self.cr, self.uw, True)

    async def _server_to_client(self) -> None:
        stream, seen = RecordStream(), 0
        while not self.server_hello.is_set():
            rec = stream.next_record()
            if rec is None:
                data = await self._read(self.ur, HANDSHAKE_TIMEOUT)
                if not data:
                    self._eof(self.cw)
                    return
                seen += len(data)
                if seen > INSPECT_BUDGET_S2C:
                    raise TLSViolation("tls-inspect-budget",
                                       "server sent too much before its ServerHello")
                stream.feed(data)
                continue
            ctype, record, payload = rec
            if ctype == CT_HANDSHAKE:
                for mtype, body in stream.handshake_messages(payload):
                    if mtype != HS_SERVER_HELLO:
                        if self.server_hello.is_set():
                            continue       # TLS 1.2: Certificate etc. in the same record
                        raise TLSViolation("tls-server-unexpected", f"message {mtype}")
                    if self.server_hello.is_set():
                        continue
                    if is_hello_retry(body):
                        self.retries += 1
                        if self.retries > 1:
                            raise TLSViolation("tls-second-retry")
                    else:
                        self.server_hello.set()
            elif ctype not in (CT_ALERT, CT_CCS):
                raise TLSViolation("tls-server-record", f"record type {ctype} before ServerHello")
            await self._send(self.cw, record, False)
        rest = stream.take_rest()
        if rest:
            await self._send(self.cw, rest, False)
        await self._pump(self.ur, self.cw, False)

    async def _pump(self, reader, writer, up) -> None:
        while True:
            try:
                data = await self._read(reader, IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                if time.monotonic() - self.last >= IDLE_TIMEOUT:
                    raise
                continue                   # the other direction is active
            if not data:
                self._eof(writer)
                return
            await self._send(writer, data, up)

    @staticmethod
    def _eof(writer) -> None:
        """Half-close: pass the end of one direction on, so the other can finish too."""
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except OSError:
            pass


# ---- HTTP front ----------------------------------------------------------------------------------
REASONS = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway", 503: "Service Unavailable",
           504: "Gateway Timeout"}


def parse_connect(head: bytes, allow: frozenset[str]) -> str:
    """The CONNECT request head (without the final blank line) -> the allowed host, or Refused."""
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("non-ascii", 400) from None
    lines = text.split("\r\n")
    if any("\n" in ln or "\r" in ln for ln in lines) or len(lines) - 1 > MAX_HEADERS:
        raise Refused("malformed", 400)
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise Refused("malformed", 400)
    method, target = parts[0], parts[1]
    if method != "CONNECT":
        raise Refused("method", 403, f"{method[:16]} is not CONNECT")
    for ln in lines[1:]:
        if ":" not in ln or ln[:1] in (" ", "\t"):
            raise Refused("malformed", 400)
    host, sep, port = target.rpartition(":")
    if not sep or port != "443":
        raise Refused("port", 403, f"target {target[:64]!r}: only port 443")
    host = host.lower()
    if host not in allow:
        raise Refused("host", 403, f"{host[:253]!r} is not allow-listed")
    return host


async def resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM),
            RESOLVE_TIMEOUT)
    except asyncio.TimeoutError:
        raise Refused("resolve-timeout", 504) from None
    except OSError as e:
        raise Refused("resolve-failed", 502, str(e)[:120]) from None
    addrs = list(dict.fromkeys(info[4][0] for info in infos))
    if not addrs:
        raise Refused("resolve-failed", 502, "no IPv4 address")
    bad = [a for a in addrs if not address_allowed(a)]
    if bad:
        raise Refused("resolve-non-global", 403, f"{host} resolves to {bad[0]}")
    return addrs


class Proxy:
    def __init__(self, allow: frozenset[str], max_clients: int = 16, resolver=resolve, log=None,
                 upstream_port: int = 443):
        self.allow = allow
        self.slots = asyncio.Semaphore(max_clients)
        self.resolver = resolver
        self.upstream_port = upstream_port      # 443 in production; tests use a local server
        self.log = log or (lambda rec: print(json.dumps(rec, sort_keys=True), flush=True))

    async def handle(self, creader, cwriter) -> None:
        peer = (cwriter.get_extra_info("peername") or ("?",))[0]
        rec = {"client": peer, "verdict": "error"}
        start = time.monotonic()
        if self.slots.locked():
            await self._reply(cwriter, 503, "busy")
            rec.update(verdict="refused", reason="busy")
            self.log(rec)
            cwriter.close()
            return
        async with self.slots:
            uwriter = None
            try:
                head, early = await asyncio.wait_for(self._read_head(creader), HEAD_TIMEOUT)
                host = parse_connect(head, self.allow)
                rec["host"] = host
                addrs = await self.resolver(host)
                rec["addresses"] = addrs
                ureader, uwriter = await self._connect(addrs)
                rec["upstream"] = uwriter.get_extra_info("peername")[0]
                cwriter.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await cwriter.drain()
                tunnel = Tunnel(host, creader, cwriter, ureader, uwriter)
                try:
                    await tunnel.run(early)
                    rec.update(verdict="closed")
                finally:
                    rec.update(sni=tunnel.sni, alpn=tunnel.alpn, client_hellos=tunnel.client_hellos,
                               hello_retries=tunnel.retries, bytes_up=tunnel.up,
                               bytes_down=tunnel.down)
            except TLSViolation as e:
                rec.update(verdict="cut", reason=e.reason, detail=e.detail)
            except Refused as e:
                rec.update(verdict="refused", reason=e.reason, status=e.status, detail=e.detail)
                await self._reply(cwriter, e.status, e.reason)
            except asyncio.TimeoutError:
                rec.update(verdict="timeout")
            except Silent:
                rec = None                 # a bare liveness probe: nothing to audit
            except (ConnectionError, OSError) as e:
                rec.update(verdict="closed", detail=type(e).__name__)
            finally:
                if rec is not None:
                    rec["seconds"] = round(time.monotonic() - start, 3)
                    self.log(rec)
                for w in (uwriter, cwriter):
                    if w is not None:
                        w.close()

    async def _read_head(self, reader) -> tuple[bytes, bytes]:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            if len(buf) > MAX_HEAD:
                raise Refused("head-too-large", 400)
            chunk = await reader.read(4096)
            if not chunk:
                if not buf:
                    raise Silent()
                raise ConnectionResetError("client closed before the request head")
            buf += chunk
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        if len(head) > MAX_HEAD:
            raise Refused("head-too-large", 400)
        return head, rest

    async def _connect(self, addrs):
        last = None
        for addr in addrs:
            try:
                return await asyncio.wait_for(asyncio.open_connection(addr, self.upstream_port),
                                              CONNECT_TIMEOUT)
            except asyncio.TimeoutError:
                last = Refused("upstream-timeout", 504)
            except OSError as e:
                last = Refused("upstream-failed", 502, type(e).__name__)
        raise last

    @staticmethod
    async def _reply(writer, status, reason) -> None:
        try:
            writer.write((f"HTTP/1.1 {status} {REASONS.get(status, 'Error')}\r\n"
                          f"X-Egress-Reason: {reason}\r\nContent-Length: 0\r\n"
                          "Connection: close\r\n\r\n").encode())
            await writer.drain()
        except (ConnectionError, OSError):
            pass


async def main() -> int:
    try:
        allow = parse_allowlist(os.environ.get("EGRESS_ALLOW", ""))
        host, _, port = os.environ.get("EGRESS_LISTEN", "0.0.0.0:3128").rpartition(":")
        max_clients = int(os.environ.get("EGRESS_MAX_CLIENTS", "16"))
        if not 1 <= max_clients <= 256:
            raise ValueError("EGRESS_MAX_CLIENTS must be 1..256")
    except ValueError as e:
        print(f"egress-proxy: {e}", file=sys.stderr)
        return 2
    proxy = Proxy(allow, max_clients)
    server = await asyncio.start_server(proxy.handle, host, int(port), backlog=64,
                                        reuse_address=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    print(json.dumps({"event": "listening", "listen": f"{host}:{port}", "allow": sorted(allow)}),
          flush=True)
    async with server:
        await stop.wait()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
