"""docker/egress_proxy.py against real sockets: the HTTP front (what may be CONNECTed), DNS pinning
(where the tunnel really goes) and the TLS gate (what the tunnel may carry: SNI == CONNECT host).

Attack reproductions are each paired with the assertion that matters: the provider side received
NOTHING (no byte, or no complete ClientHello) - not merely that the client saw an error. The
compatibility tests run real OpenSSL TLS 1.3 and 1.2 handshakes (certificate verified) through the
gate. Everything is local: a scripted TCP server or a TLS echo server stands in for the provider.
"""
import asyncio
import ipaddress
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker"))
import egress_proxy as ep  # noqa: E402

ALLOW = frozenset({"allowed.test", "other.test"})


# ---- TLS byte builders ---------------------------------------------------------------------------
def ext(etype: int, data: bytes) -> bytes:
    return struct.pack(">HH", etype, len(data)) + data


def sni_ext(*names: str, kind: int = 0) -> bytes:
    entries = b"".join(bytes([kind]) + struct.pack(">H", len(n)) + n.encode() for n in names)
    return ext(0, struct.pack(">H", len(entries)) + entries)


def client_hello_body(sni="allowed.test", exts=None, trailing=b"") -> bytes:
    if exts is None:
        exts = [sni_ext(sni)] if sni is not None else []
    e = b"".join(exts)
    return (b"\x03\x03" + bytes(32) + b"\x00" + struct.pack(">H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack(">H", len(e)) + e + trailing)


def hs(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def rec(ctype: int, payload: bytes) -> bytes:
    return bytes([ctype, 3, 1]) + struct.pack(">H", len(payload)) + payload


def ch(**kw) -> bytes:
    return rec(22, hs(1, client_hello_body(**kw)))


def server_hello(hrr=False) -> bytes:
    rnd = ep.HRR_RANDOM if hrr else bytes(range(32))
    body = b"\x03\x03" + rnd + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack(">H", 0)
    return rec(22, hs(2, body))


CCS = rec(20, b"\x01")
APPDATA = rec(23, b"\x17" * 40)


# ---- harness: one event loop in a thread hosts the proxy and the stand-in providers --------------
class Upstream:
    """Scripted provider: records every byte; after the n-th complete ClientHello it sends
    script[n] (e.g. a HelloRetryRequest, then a ServerHello + application data)."""

    def __init__(self, script=()):
        self.script = list(script)
        self.received = bytearray()
        self.hellos = []
        self.connections = 0

    async def handle(self, reader, writer):
        self.connections += 1
        stream = ep.RecordStream()
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                self.received += data
                stream.feed(data)
                while (r := stream.next_record()) is not None:
                    if r[0] != 22:
                        continue
                    for mtype, body in stream.handshake_messages(r[2]):
                        if mtype == 1:
                            self.hellos.append(ep.parse_client_hello(body)["sni"])
                            i = len(self.hellos) - 1
                            if i < len(self.script):
                                writer.write(self.script[i])
                                await writer.drain()
        except (ep.TLSViolation, ConnectionError):
            pass
        writer.close()


class Harness:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.logs = []

    def run(self, coro, timeout=20):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def serve(self, handler, ssl_ctx=None) -> int:
        async def start():
            srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
            return srv.sockets[0].getsockname()[1]
        return self.run(start())

    def proxy(self, upstream_port, allow=ALLOW, max_clients=16, resolver=None) -> int:
        async def fixed(host):
            return ["127.0.0.1"]
        p = ep.Proxy(allow, max_clients, resolver=resolver or fixed, log=self.logs.append,
                     upstream_port=upstream_port)
        return self.serve(p.handle)

    def wait_log(self, n=1, timeout=10.0):
        end = time.monotonic() + timeout
        while len(self.logs) < n and time.monotonic() < end:
            time.sleep(0.02)
        assert len(self.logs) >= n, f"proxy logged {self.logs}"
        return self.logs[n - 1]

    def close(self):
        async def cancel_all():
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            self.run(cancel_all(), timeout=10)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(5)


@pytest.fixture
def h():
    harness = Harness()
    yield harness
    harness.close()


def connect(port, target="allowed.test:443", raw=None):
    """Sends a CONNECT (or `raw` request bytes); returns (socket, status, headers)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    if raw is None:
        raw = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
    s.sendall(raw)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n")[0].decode()
    lines = head.split("\r\n")
    status = int(lines[0].split(" ")[1]) if lines and lines[0].startswith("HTTP/") else 0
    headers = dict(ln.split(": ", 1) for ln in lines[1:] if ": " in ln)
    return s, status, headers


def is_cut(s, timeout=10.0) -> bool:
    """The proxy closed the tunnel (EOF or reset) without sending anything further."""
    s.settimeout(timeout)
    try:
        return s.recv(65536) == b""
    except ConnectionResetError:
        return True


# ==== the HTTP front: what may be CONNECTed =======================================================
@pytest.mark.parametrize("target,reason", [
    ("1.1.1.1:443", "host"),                    # IP literal
    ("[::1]:443", "host"),                      # IPv6 literal
    ("169.254.169.254:443", "host"),            # metadata
    ("100.107.22.84:443", "host"),              # the tailnet address of the host
    ("evil.test:443", "host"),                  # not allow-listed
    ("allowed.test.evil.test:443", "host"),     # look-alike suffix
    ("evilallowed.test:443", "host"),
    ("allowed.test.:443", "host"),              # trailing dot is not the listed name
    ("allowed.test:80", "port"),
    ("allowed.test:0443", "port"),
    ("allowed.test:443x", "port"),
    ("allowed.test", "port"),
])
def test_connect_targets_outside_the_policy_are_refused_with_403(h, target, reason):
    up = Upstream()
    port = h.proxy(h.serve(up.handle))
    s, status, headers = connect(port, target)
    assert status == 403 and headers.get("X-Egress-Reason") == reason, (status, headers)
    assert up.connections == 0                  # never even dialled


@pytest.mark.parametrize("raw", [
    b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
    b"POST http://allowed.test:443/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
    b"connect allowed.test:443 HTTP/1.1\r\n\r\n",          # methods are case-sensitive
])
def test_only_connect_is_accepted_plain_http_forwarding_is_refused(h, raw):
    up = Upstream()
    port = h.proxy(h.serve(up.handle))
    s, status, headers = connect(port, raw=raw)
    assert status == 403 and headers["X-Egress-Reason"] == "method"
    assert up.connections == 0


@pytest.mark.parametrize("raw", [
    b"CONNECT allowed.test:443 HTTP/2\r\n\r\n",
    b"CONNECT allowed.test:443\r\n\r\n",
    b"CONNECT allowed.test:443 HTTP/1.1\r\nno-colon-header\r\n\r\n",
    b"CONNECT allowed.test:443 HTTP/1.1\r\n folded: header\r\n\r\n",
    b"CONNECT allowed.test:443 HTTP/1.1\nHost: x\r\n\r\n",
    "CONNECT allowed.test:443 HTTP/1.1\r\nX: é\r\n\r\n".encode(),
    b"CONNECT allowed.test:443 HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 9000 + b"\r\n\r\n",
])
def test_malformed_or_oversized_requests_are_refused_with_400(h, raw):
    up = Upstream()
    port = h.proxy(h.serve(up.handle))
    s, status, _ = connect(port, raw=raw)
    assert status == 400 and up.connections == 0


def test_the_host_comparison_is_case_insensitive_but_otherwise_exact(h):
    up = Upstream(script=[server_hello()])
    port = h.proxy(h.serve(up.handle))
    s, status, _ = connect(port, "ALLOWED.Test:443")
    assert status == 200
    s.sendall(ch(sni="allowed.test"))
    assert s.recv(65536).startswith(b"\x16\x03")         # the provider's ServerHello came back


def test_a_full_proxy_says_busy_not_forbidden(h):
    up = Upstream()
    port = h.proxy(h.serve(up.handle), max_clients=1)
    s1, status1, _ = connect(port)
    assert status1 == 200
    s2, status2, headers = connect(port)
    assert status2 == 503 and headers["X-Egress-Reason"] == "busy"


def test_an_upstream_failure_is_502_never_a_policy_403(h):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()
    port = h.proxy(dead_port)
    s, status, headers = connect(port)
    assert status == 502 and headers["X-Egress-Reason"] == "upstream-failed"


def test_a_bare_liveness_probe_is_not_logged_but_a_partial_request_is(h):
    port = h.proxy(h.serve(Upstream().handle))
    socket.create_connection(("127.0.0.1", port), timeout=5).close()       # the healthcheck's nc -z
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"CONNECT allowed.te")
    s.close()
    log = h.wait_log()
    assert len(h.logs) == 1 and log["verdict"] == "closed", h.logs


def test_a_slow_request_head_times_out(h, monkeypatch):
    monkeypatch.setattr(ep, "HEAD_TIMEOUT", 0.5)
    port = h.proxy(h.serve(Upstream().handle))
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\n")      # never finished
    assert is_cut(s)
    assert h.wait_log()["verdict"] == "timeout"


# ==== DNS pinning: where the tunnel really goes ===================================================
@pytest.mark.parametrize("addr,ok", [
    ("1.1.1.1", True), ("104.18.32.7", True), ("8.8.8.8", True),
    ("127.0.0.1", False), ("10.0.2.2", False), ("10.0.2.3", False), ("172.17.0.1", False),
    ("192.168.1.1", False), ("100.64.0.1", False), ("100.107.22.84", False),
    ("100.100.100.100", False), ("169.254.169.254", False), ("0.0.0.0", False),
    ("224.0.0.1", False), ("240.0.0.1", False), ("255.255.255.255", False),
    ("192.0.2.1", False), ("198.18.0.1", False),
    ("2606:4700::1111", False), ("::1", False), ("::ffff:1.1.1.1", False), ("not-an-ip", False),
])
def test_only_global_unicast_ipv4_is_ever_dialled(addr, ok):
    assert ep.address_allowed(addr) is ok


def _gai(answers):
    async def fake(host, port, family=0, type=0, **kw):
        assert family == socket.AF_INET                         # IPv4 only: there is no v6 route
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answers]
    return fake


@pytest.mark.parametrize("answers", [
    ["127.0.0.1"],                               # rebinding to the proxy's own loopback
    ["100.107.22.84"],                           # ... to the host's tailnet address
    ["1.1.1.1", "192.168.1.1"],                  # one bad record poisons the whole answer
    ["169.254.169.254"],
])
def test_a_name_that_resolves_anywhere_non_global_is_refused(monkeypatch, answers):
    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _gai(answers))
        with pytest.raises(ep.Refused) as e:
            await ep.resolve("allowed.test")
        return e.value
    err = asyncio.run(scenario())
    assert err.status == 403 and err.reason == "resolve-non-global"


def test_a_global_answer_is_used_exactly_as_validated(monkeypatch):
    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _gai(["1.1.1.1", "1.0.0.1"]))
        return await ep.resolve("allowed.test")
    assert asyncio.run(scenario()) == ["1.1.1.1", "1.0.0.1"]


def test_resolution_failure_is_a_502(monkeypatch):
    async def scenario():
        async def boom(*a, **k):
            raise socket.gaierror(socket.EAI_NONAME, "no")
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", boom)
        with pytest.raises(ep.Refused) as e:
            await ep.resolve("allowed.test")
        return e.value
    assert asyncio.run(scenario()).status == 502


def test_the_proxy_dials_the_address_it_validated_not_a_fresh_lookup(h):
    """DNS rebinding between check and use is impossible: the resolver is consulted once and
    the connection goes to that literal address."""
    calls = []

    async def resolver(host):
        calls.append(host)
        return ["127.0.0.1"]
    up = Upstream(script=[server_hello()])
    port = h.proxy(h.serve(up.handle), resolver=resolver)
    s, status, _ = connect(port)
    assert status == 200 and calls == ["allowed.test"]
    s.sendall(ch(sni="allowed.test"))
    assert s.recv(65536).startswith(b"\x16\x03")
    s.close()
    assert h.wait_log()["upstream"] == "127.0.0.1" and calls == ["allowed.test"]


# ==== the TLS gate: what the tunnel may carry =====================================================
def tunnel(h, script=(), target="allowed.test:443"):
    up = Upstream(script=script)
    port = h.proxy(h.serve(up.handle))
    s, status, _ = connect(port, target)
    assert status == 200
    return s, up


def test_a_matching_client_hello_reaches_the_provider_and_the_tunnel_is_spliced(h):
    s, up = tunnel(h, script=[server_hello() + APPDATA])
    s.sendall(ch(sni="allowed.test"))
    reply = s.recv(65536)
    assert reply.startswith(server_hello())
    s.sendall(CCS + APPDATA + b"opaque bytes are fine after the handshake")
    time.sleep(0.3)
    assert up.hellos == ["allowed.test"] and up.received.endswith(b"after the handshake")


@pytest.mark.parametrize("hello,reason", [
    (ch(sni="other.test"), "tls-sni-mismatch"),          # another ALLOW-LISTED name: still refused
    (ch(sni="evil.test"), "tls-sni-mismatch"),           # domain/SNI swap on a shared CDN
    (ch(sni="ALLOWED.TEST.evil.test"), "tls-sni-mismatch"),
    (ch(sni=None), "tls-no-sni"),
    (ch(exts=[sni_ext("allowed.test"), ext(0xFE0D, b"\x00" * 40)]), "tls-ech"),
    (ch(exts=[sni_ext("allowed.test"), ext(0xFFCE, b"\x00" * 8)]), "tls-ech"),
    (ch(exts=[sni_ext("allowed.test", "evil.test")]), "tls-sni-list"),
    (ch(exts=[sni_ext("allowed.test", kind=1)]), "tls-sni-list"),
    (ch(exts=[sni_ext("allowed.test"), sni_ext("evil.test")]), "tls-malformed"),
    (ch(sni="allowed.test", trailing=b"\x00"), "tls-malformed"),
    (rec(22, hs(1, client_hello_body()[:30])), "tls-malformed"),
    (rec(22, hs(1, b"\x03\x03" + bytes(32) + b"\x00\x00\x00\x01\x00")), "tls-malformed"),
    (APPDATA, "tls-not-handshake"),
    (CCS + ch(), "tls-not-handshake"),
    (rec(22, hs(2, b"\x03\x03" + bytes(34))), "tls-unexpected-handshake"),
    (b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n", "tls-not-tls"),
    (bytes([22, 3, 1, 0xFF, 0xFF]) + b"\x00" * 20, "tls-malformed"),   # record > TLS maximum
])
def test_a_client_hello_that_does_not_name_exactly_the_connect_host_never_reaches_the_provider(
        h, hello, reason):
    s, up = tunnel(h)
    s.sendall(hello)
    assert is_cut(s)
    log = h.wait_log()
    assert log["verdict"] == "cut" and log["reason"] == reason, log
    time.sleep(0.2)
    assert up.hellos == [], up.hellos            # the provider never saw a complete ClientHello
    if reason not in ("tls-not-handshake",):
        assert not up.received or not up.received.endswith(hello)


def test_a_fragmented_client_hello_is_judged_as_a_whole(h):
    body = hs(1, client_hello_body(sni="evil.test"))
    s, up = tunnel(h)
    s.sendall(rec(22, body[:25]))              # fragment 1: harmless on its own, forwarded
    s.sendall(rec(22, body[25:]))              # fragment 2 completes a bad ClientHello: held back
    assert is_cut(s)
    time.sleep(0.2)
    assert up.hellos == [] and h.wait_log()["reason"] == "tls-sni-mismatch"


def test_a_fragmented_good_client_hello_passes(h):
    body = hs(1, client_hello_body(sni="allowed.test"))
    s, up = tunnel(h, script=[server_hello()])
    s.sendall(rec(22, body[:25]) + rec(22, body[25:]))
    assert s.recv(65536).startswith(b"\x16\x03")
    assert up.hellos == ["allowed.test"]


def test_hello_retry_request_second_client_hello_must_match_too(h):
    """TLS 1.3 HelloRetryRequest: the client sends a second plaintext ClientHello. Swapping the
    SNI there (after an innocent first one) is the bypass this guards against."""
    s, up = tunnel(h, script=[server_hello(hrr=True)])
    s.sendall(ch(sni="allowed.test"))
    assert s.recv(65536).startswith(server_hello(hrr=True))
    s.sendall(CCS + ch(sni="evil.test"))       # middlebox-compat CCS, then the swapped hello
    assert is_cut(s)
    time.sleep(0.2)
    assert up.hellos == ["allowed.test"] and h.wait_log()["reason"] == "tls-sni-mismatch"


def test_hello_retry_request_with_a_matching_second_hello_works(h):
    s, up = tunnel(h, script=[server_hello(hrr=True), server_hello() + APPDATA])
    s.sendall(ch(sni="allowed.test"))
    assert s.recv(65536).startswith(server_hello(hrr=True))
    s.sendall(CCS + ch(sni="allowed.test"))
    assert s.recv(65536).startswith(server_hello())
    s.sendall(APPDATA)
    time.sleep(0.2)
    assert up.hellos == ["allowed.test", "allowed.test"] and up.received.endswith(APPDATA)


def test_a_second_client_hello_without_hello_retry_request_is_cut(h):
    s, up = tunnel(h)
    s.sendall(ch(sni="allowed.test") + ch(sni="allowed.test"))
    assert is_cut(s)
    assert h.wait_log()["reason"] == "tls-extra-client-hello"


def test_a_client_hello_after_the_server_hello_is_cut(h):
    s, up = tunnel(h, script=[server_hello()])
    s.sendall(ch(sni="allowed.test"))
    assert s.recv(65536).startswith(server_hello())
    s.sendall(ch(sni="evil.test"))             # plaintext, before the client's CCS
    assert is_cut(s)
    assert h.wait_log()["reason"] == "tls-client-hello-after-server-hello"


def test_a_second_hello_retry_request_is_cut(h):
    s, up = tunnel(h, script=[server_hello(hrr=True), server_hello(hrr=True)])
    s.sendall(ch(sni="allowed.test"))
    s.recv(65536)
    s.sendall(ch(sni="allowed.test"))
    assert is_cut(s)
    assert h.wait_log()["reason"] == "tls-second-retry"


def test_early_data_after_a_checked_hello_is_forwarded(h):
    s, up = tunnel(h, script=[server_hello()])
    s.sendall(ch(sni="allowed.test") + APPDATA)      # TLS 1.3 0-RTT
    assert s.recv(65536).startswith(server_hello())
    time.sleep(0.2)
    assert up.received.endswith(APPDATA)


def test_a_provider_that_sends_data_before_its_server_hello_is_cut(h):
    s, up = tunnel(h, script=[APPDATA])
    s.sendall(ch(sni="allowed.test"))
    assert is_cut(s)
    assert h.wait_log()["reason"] == "tls-server-record"


def test_a_tunnel_without_a_client_hello_times_out(h, monkeypatch):
    monkeypatch.setattr(ep, "HELLO_TIMEOUT", 0.5)
    s, up = tunnel(h)
    assert is_cut(s)
    assert h.wait_log()["verdict"] == "timeout"


def test_the_inspection_budget_bounds_pre_handshake_data(h, monkeypatch):
    monkeypatch.setattr(ep, "INSPECT_BUDGET_C2S", 4096)
    s, up = tunnel(h)
    s.sendall(ch(sni="allowed.test") + APPDATA * 200)
    assert is_cut(s)
    assert h.wait_log()["reason"] == "tls-inspect-budget"


# ==== compatibility: real TLS through the gate ====================================================
@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-days", "2", "-subj", "/CN=allowed.test",
         "-addext", "subjectAltName=DNS:allowed.test,DNS:other.test",
         "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem")],
        check=True, capture_output=True)
    return d


def tls_server(h, certs):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certs / "cert.pem", certs / "key.pem")
    seen = {"handshakes": 0}

    async def echo(reader, writer):
        seen["handshakes"] += 1
        try:
            data = await reader.read(1024)
            writer.write(b"pong:" + data)
            await writer.drain()
        except (ssl.SSLError, ConnectionError):
            pass
        writer.close()
    return h.serve(echo, ssl_ctx=ctx), seen


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2])
def test_a_real_tls_client_with_the_right_sni_works_through_the_gate(h, certs, version):
    up_port, seen = tls_server(h, certs)
    port = h.proxy(up_port)
    s, status, _ = connect(port)
    assert status == 200
    ctx = ssl.create_default_context(cafile=str(certs / "cert.pem"))
    ctx.minimum_version = ctx.maximum_version = version
    with ctx.wrap_socket(s, server_hostname="allowed.test") as t:
        names = {ssl.TLSVersion.TLSv1_3: "TLSv1.3", ssl.TLSVersion.TLSv1_2: "TLSv1.2"}
        assert t.version() == names[version]
        t.sendall(b"ping")
        assert t.recv(1024) == b"pong:ping"
    log = h.wait_log()
    assert log["sni"] == "allowed.test" and log["client_hellos"] == 1


def test_a_real_tls_client_naming_another_server_is_stopped_before_the_provider_sees_it(h, certs):
    """The CDN case: the certificate even covers both names (one shared edge), the CONNECT says
    allowed.test, the TLS client asks for other.test. The provider never gets the ClientHello."""
    up_port, seen = tls_server(h, certs)
    port = h.proxy(up_port)
    s, status, _ = connect(port)
    ctx = ssl.create_default_context(cafile=str(certs / "cert.pem"))
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        with ctx.wrap_socket(s, server_hostname="other.test") as t:
            t.sendall(b"ping")
            t.recv(1024)
    log = h.wait_log()
    assert log["verdict"] == "cut" and log["reason"] == "tls-sni-mismatch"
    time.sleep(0.2)
    assert seen["handshakes"] == 0             # no TLS session was ever established upstream


# ==== configuration ===============================================================================
@pytest.mark.parametrize("raw", [
    "", " , ", "*.openai.com", "1.2.3.4", "localhost", "exa mple.com", "ex_ample.com",
    "münchen.de", "a..b.com", "api.openai.com.", "-a.com", "a-.com", "a.123",
    "x" * 64 + ".com", "api.openai.com:443", "http://api.openai.com",
])
def test_the_allowlist_rejects_anything_but_exact_hostnames(raw):
    with pytest.raises(ValueError):
        ep.parse_allowlist(raw)


def test_the_allowlist_is_normalised_to_lower_case():
    assert ep.parse_allowlist(" API.OpenAI.com,chatgpt.com ") == {"api.openai.com", "chatgpt.com"}


def test_main_refuses_to_start_without_a_valid_allowlist(monkeypatch):
    for value in ("", "*.x.com"):
        monkeypatch.setenv("EGRESS_ALLOW", value)
        assert asyncio.run(ep.main()) == 2


def test_the_parser_never_accepts_a_server_name_that_is_not_ascii():
    name = "éx.de".encode()
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    body = client_hello_body(exts=[ext(0, struct.pack(">H", len(entry)) + entry)])
    with pytest.raises(ep.TLSViolation) as e:
        ep.parse_client_hello(body)
    assert e.value.reason == "tls-sni-invalid"


def test_ipaddress_semantics_the_policy_relies_on():
    # if a future Python changed these, the address policy would silently change with it
    assert not ipaddress.ip_address("100.64.0.1").is_global
    assert not ipaddress.ip_address("192.0.0.1").is_global
    assert ipaddress.ip_address("1.1.1.1").is_global
