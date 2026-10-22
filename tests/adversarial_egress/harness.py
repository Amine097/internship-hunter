"""Black-box harness for docker/egress_proxy.py.

Everything runs inside ONE private user+network+mount namespace (`unshare -Urnm`), so nothing touches
the host network, no port can collide with another session, and nothing needs privileges:

  * the REAL, UNMODIFIED proxy process (`python3.12 -IB docker/egress_proxy.py`) with the production
    port (443 upstream), its real `resolve()` (libc getaddrinfo) and its real address policy;
  * /etc/hosts and /etc/resolv.conf are bind-mounted over with ours, so the allow-listed names resolve
    to addresses we choose: a genuinely GLOBAL address added to `lo` (93.184.216.34) for the "provider",
    and private / loopback / link-local / CGNAT / reserved addresses for the DNS-rebinding cases;
  * the "provider" is a recording TCP server (and, for positive controls, a real OpenSSL TLS server
    with a private CA): what the upstream RECEIVED is the ground truth of every assertion;
  * clients are raw sockets that hand-craft HTTP heads, TLS records and ClientHellos.

Run:  unshare -Urnm python3 harness.py [--only PREFIX] [--json out.json]
(`run()` re-executes itself in the namespace when it is not already in one.)
"""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PROXY_PY = os.environ.get("EGRESS_PROXY_PY") or os.path.join(REPO, "docker", "egress_proxy.py")
PYTHON = os.environ.get("EGRESS_PYTHON") or sys.executable

PROVIDER_A, PROVIDER_B = "93.184.216.34", "93.184.216.35"      # global unicast, on `lo` in the namespace
NAME_A, NAME_B = "api.provider-a.test", "api.provider-b.test"
PROXY = ("127.0.0.1", 3128)

# name -> addresses it resolves to (written to /etc/hosts); everything here is ALLOW-LISTED, so the only
# thing standing between the agent and these addresses is resolve() / address_allowed()
HOSTS = {
    NAME_A: [PROVIDER_A],
    NAME_B: [PROVIDER_B],
    "priv10.provider.test": ["10.9.9.9"],
    "priv172.provider.test": ["172.31.9.9"],
    "priv192.provider.test": ["192.168.9.9"],
    "loop.provider.test": ["127.0.0.2"],
    "linklocal.provider.test": ["169.254.169.254"],
    "cgnat.provider.test": ["100.100.100.100"],
    "cgnat2.provider.test": ["100.64.1.1"],
    "zero.provider.test": ["0.0.0.0"],
    "bcast.provider.test": ["255.255.255.255"],
    "multicast.provider.test": ["224.0.0.251"],
    "classe.provider.test": ["240.0.0.1"],
    "bench.provider.test": ["198.18.0.7"],
    "doc.provider.test": ["203.0.113.5"],
    "ietf.provider.test": ["192.0.0.1"],
    "mixed1.provider.test": [PROVIDER_A, "10.9.9.9"],       # global first, private second
    "mixed2.provider.test": ["10.9.9.9", PROVIDER_A],       # private first
    "v6only.provider.test": ["::1"],
    "v6mapped.provider.test": ["::ffff:10.9.9.9"],
    "flip.provider.test": [PROVIDER_A],                      # rewritten mid-run (DNS rebinding)
}
ALLOW = ",".join(HOSTS) + ",nxdomain.provider.test"           # the last one is not in /etc/hosts
DIAL_TRAPS = ["10.9.9.9", "172.31.9.9", "192.168.9.9", "127.0.0.2", "169.254.169.254", "100.100.100.100",
              "100.64.1.1", "198.18.0.7", "203.0.113.5", "192.0.0.1", "224.0.0.251"]

RESULTS: list[dict] = []
_current: dict = {}


# =============================================================================== namespace bootstrap
def in_namespace() -> bool:
    return os.environ.get("EGRESS_HARNESS_NS") == "1"


def reexec() -> None:
    env = dict(os.environ, EGRESS_HARNESS_NS="1")
    os.execvpe("unshare", ["unshare", "-Urnm", sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env)


def sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=True)


def setup_namespace(work: str) -> None:
    sh("ip link set lo up")
    for ip in [PROVIDER_A, PROVIDER_B, *DIAL_TRAPS]:
        sh(f"ip addr add {ip}/32 dev lo")
    hosts = ["127.0.0.1 localhost"]
    for name, addrs in HOSTS.items():
        for a in addrs:
            hosts.append(f"{a} {name}")
    path = os.path.join(work, "hosts")
    with open(path, "w") as f:
        f.write("\n".join(hosts) + "\n")
    with open(os.path.join(work, "resolv.conf"), "w") as f:
        f.write("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")      # nothing listens: instant failure
    with open(os.path.join(work, "nsswitch.conf"), "w") as f:
        f.write("hosts: files dns\n")
    sh(f"mount --bind {path} /etc/hosts")
    sh(f"mount --bind {work}/resolv.conf /etc/resolv.conf")
    if os.path.exists("/etc/nsswitch.conf"):
        sh(f"mount --bind {work}/nsswitch.conf /etc/nsswitch.conf")


def rewrite_hosts(work: str, name: str, addrs: list[str]) -> None:
    """Change what an allow-listed name resolves to, in place (the bind mount follows the file)."""
    lines = [ln for ln in open(os.path.join(work, "hosts")).read().splitlines() if ln.split()[-1:] != [name]]
    lines += [f"{a} {name}" for a in addrs]
    with open(os.path.join(work, "hosts"), "w") as f:
        f.write("\n".join(lines) + "\n")


# =============================================================================== certificates
def make_pki(work: str) -> tuple[str, str, str]:
    ca_key, ca_crt = f"{work}/ca.key", f"{work}/ca.crt"
    sh(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {ca_key} -out {ca_crt} -days 2 -subj /CN=review-ca "
       f"2>/dev/null")
    key, csr, crt, ext = f"{work}/srv.key", f"{work}/srv.csr", f"{work}/srv.crt", f"{work}/ext.cnf"
    with open(ext, "w") as f:
        f.write(f"subjectAltName=DNS:{NAME_A},DNS:{NAME_B},DNS:other.example.test\n")
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {key} -out {csr} -subj /CN={NAME_A} 2>/dev/null")
    sh(f"openssl x509 -req -in {csr} -CA {ca_crt} -CAkey {ca_key} -CAcreateserial -out {crt} -days 2 "
       f"-extfile {ext} 2>/dev/null")
    return ca_crt, crt, key


# =============================================================================== the "provider"
class Conn:
    def __init__(self, peer, address):
        self.peer, self.address = peer, address
        self.chunks: list[bytes] = []
        self.start = time.monotonic()
        self.sni = None
        self.http = b""
        self.alpn = None

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


class Upstream:
    """Recording servers on the provider and trap addresses.

    mode "raw": reads and records, replies with `script(conn, sock)` if given (else nothing).
    mode "tls": a real TLS server (private CA); records the SNI it saw and the HTTP request it decrypted."""

    def __init__(self, ctx=None):
        self.conns: list[Conn] = []
        self.lock = threading.Lock()
        self.ctx = ctx
        self.mode = {}
        self.script = {}
        self.stop = False
        self.servers = []

    def listen(self, ip, mode="raw"):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, 443))
        s.listen(64)
        self.mode[ip] = mode
        self.servers.append(s)
        threading.Thread(target=self._accept, args=(s, ip), daemon=True).start()

    def _accept(self, s, ip):
        while not self.stop:
            try:
                c, peer = s.accept()
            except OSError:
                return
            conn = Conn(peer, ip)
            with self.lock:
                self.conns.append(conn)
            threading.Thread(target=self._serve, args=(c, conn), daemon=True).start()

    def _serve(self, c, conn):
        try:
            c.settimeout(5)
            if self.mode[conn.address] == "tls":
                return self._serve_tls(c, conn)
            script = self.script.get(conn.address)
            if script:
                return script(conn, c)
            while True:
                data = c.recv(65536)
                if not data:
                    return
                conn.chunks.append(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def _serve_tls(self, c, conn):
        def on_sni(sock, name, ctx):
            conn.sni = name
        self.ctx.sni_callback = on_sni
        t = self.ctx.wrap_socket(c, server_side=True)
        conn.alpn = t.selected_alpn_protocol()
        conn.http = t.recv(65536)
        conn.chunks.append(conn.http)
        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def mark(self) -> int:
        with self.lock:
            return len(self.conns)

    def since(self, mark: int) -> list[Conn]:
        time.sleep(0.25)
        with self.lock:
            return self.conns[mark:]

    def bytes_since(self, mark: int) -> int:
        return sum(len(c.data) for c in self.since(mark))


# =============================================================================== the proxy under test
class ProxyProc:
    def __init__(self, work, allow=ALLOW, extra_env=None):
        self.log_path = os.path.join(work, "proxy.log")
        self.logf = open(self.log_path, "wb")
        env = {"PATH": os.environ["PATH"], "EGRESS_ALLOW": allow, "EGRESS_LISTEN": f"{PROXY[0]}:{PROXY[1]}"}
        env.update(extra_env or {})
        self.p = subprocess.Popen([PYTHON, "-IB", PROXY_PY], env=env, stdout=self.logf, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                socket.create_connection(PROXY, timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("proxy did not start: " + open(self.log_path).read())

    def lines(self) -> list[dict]:
        out = []
        for ln in open(self.log_path, errors="replace").read().splitlines():
            try:
                out.append(json.loads(ln))
            except ValueError:
                out.append({"raw": ln})
        return out

    def mark(self) -> int:
        return len(self.lines())

    def since(self, mark, settle=0.35):
        """Audit lines logged since `mark`. Waits (up to 3 s) for the first one, then lets the rest settle."""
        end = time.monotonic() + 3.0
        while len(self.lines()) <= mark and time.monotonic() < end:
            time.sleep(0.05)
        time.sleep(settle)
        return self.lines()[mark:]

    def wait_quiet(self, settle=0.5):
        """Let in-flight connections of the previous case finish logging."""
        time.sleep(settle)

    def rss_kb(self) -> int:
        for ln in open(f"/proc/{self.p.pid}/status"):
            if ln.startswith("VmRSS:"):
                return int(ln.split()[1])
        return -1

    def fds(self) -> int:
        return len(os.listdir(f"/proc/{self.p.pid}/fd"))

    def alive(self) -> bool:
        return self.p.poll() is None

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()


# =============================================================================== client helpers
def connect(timeout=5) -> socket.socket:
    s = socket.create_connection(PROXY, timeout=timeout)
    return s


def read_head(s, limit=4096, timeout=3) -> bytes:
    s.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < limit:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    return buf


def status_of(head: bytes) -> tuple[str, str]:
    """('403', 'host') from a proxy answer; ('', '') if there is none."""
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    reason = re.search(rb"X-Egress-Reason: ([^\r]*)", head)
    return (m.group(1).decode() if m else "", reason.group(1).decode() if reason else "")


def request(raw: bytes, *, timeout=3, read_more=False) -> tuple[str, str, bytes]:
    """Send raw bytes, return (status, reason, everything the proxy sent back)."""
    s = connect()
    try:
        s.sendall(raw)
        head = read_head(s, timeout=timeout)
        if read_more:
            s.settimeout(0.5)
            try:
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    head += d
            except (socket.timeout, OSError):
                pass
        st, rs = status_of(head)
        return st, rs, head
    finally:
        s.close()


def connect_line(target: str, extra="") -> bytes:
    return f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{extra}\r\n".encode()


def tunnel(host=NAME_A) -> socket.socket:
    """Open a tunnel to an allow-listed host; returns the socket after the 200."""
    s = connect()
    s.sendall(connect_line(f"{host}:443"))
    head = read_head(s)
    if status_of(head)[0] != "200":
        s.close()
        raise RuntimeError(f"tunnel refused: {head[:100]!r}")
    return s


def drain(s, wait=1.0) -> tuple[bytes, bool]:
    """Everything the proxy sends until it closes (or `wait` seconds). Returns (data, closed_by_peer)."""
    s.settimeout(0.3)
    end, out, closed = time.monotonic() + wait, b"", False
    while time.monotonic() < end:
        try:
            d = s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            closed = True
            break
        if not d:
            closed = True
            break
        out += d
    return out, closed


# ---- TLS record / ClientHello crafting -----------------------------------------------------------
def record(ctype: int, payload: bytes, ver=0x0303) -> bytes:
    return struct.pack(">BHH", ctype, ver, len(payload)) + payload


def hs(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def ext(etype: int, data: bytes) -> bytes:
    return struct.pack(">HH", etype, len(data)) + data


def sni_ext(*names: bytes, kind=0) -> bytes:
    lst = b"".join(bytes([kind]) + struct.pack(">H", len(n)) + n for n in names)
    return ext(0, struct.pack(">H", len(lst)) + lst)


def client_hello(sni: bytes | None = NAME_A.encode(), *, exts_extra=(), sni_exts=None, suites=b"\x13\x01\x13\x02\xc0\x2f",
                 session_id=b"\x11" * 32, compression=b"\x00", tail=b"", legacy_version=0x0303, alpn=True,
                 raw_exts=None, no_exts=False) -> bytes:
    """A ClientHello HANDSHAKE MESSAGE (type + length + body)."""
    body = struct.pack(">H", legacy_version) + secrets.token_bytes(32)
    body += bytes([len(session_id)]) + session_id
    body += struct.pack(">H", len(suites)) + suites
    body += bytes([len(compression)]) + compression
    if not no_exts:
        if raw_exts is not None:
            e = raw_exts
        else:
            parts = []
            if sni_exts is not None:
                parts += list(sni_exts)
            elif sni is not None:
                parts.append(sni_ext(sni))
            parts.append(ext(43, b"\x03\x03\x04"))                       # supported_versions 1.3,1.2 (the form is irrelevant)
            parts.append(ext(10, b"\x00\x02\x00\x1d"))                   # supported_groups
            if alpn:
                parts.append(ext(16, b"\x00\x0c\x02h2\x08http/1.1"))
            parts += list(exts_extra)
            e = b"".join(parts)
        body += struct.pack(">H", len(e)) + e
    body += tail
    return hs(1, body)


def fragment(data: bytes, sizes) -> list[bytes]:
    out, pos, i = [], 0, 0
    sizes = list(sizes)
    while pos < len(data):
        n = sizes[i] if i < len(sizes) else sizes[-1]
        out.append(data[pos:pos + n])
        pos += n
        i += 1
    return out


def server_hello(hrr=False) -> bytes:
    random = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") if hrr else secrets.token_bytes(32)
    body = b"\x03\x03" + random + b"\x20" + b"\x22" * 32 + b"\x13\x01" + b"\x00" + b"\x00\x00"
    return record(22, hs(2, body))


# =============================================================================== case registry
def case(cid: str, title: str):
    def deco(fn):
        fn.cid, fn.title = cid, title
        CASES.append(fn)
        return fn
    return deco


CASES: list = []
CTX: dict = {}


def verdict(cid, title, ok, observed, expect, note=""):
    RESULTS.append({"id": cid, "title": title, "ok": bool(ok), "observed": observed, "expect": expect, "note": note})
    flag = "PASS" if ok else "FAIL"
    print(f"{flag}  {cid:<8} {title}\n        expect: {expect}\n        observed: {observed}" + (f"\n        note: {note}" if note else ""),
          flush=True)


def up_none(since) -> bool:
    return CTX["up"].bytes_since(since) == 0


from cases import register  # noqa: E402  (the cases live next to this file)


def main() -> int:
    only = None
    out_json = None
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--only":
            only = args.pop(0)
        elif a == "--json":
            out_json = args.pop(0)
    work = tempfile.mkdtemp(prefix="egress-bb-")
    setup_namespace(work)
    ca, crt, key = make_pki(work)
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.load_cert_chain(crt, key)
    up = Upstream(tls_ctx)
    up.listen(PROVIDER_A, "raw")
    up.listen(PROVIDER_B, "tls")
    for ip in DIAL_TRAPS:
        up.listen(ip, "raw")
    px = ProxyProc(work)
    CTX.update(up=up, px=px, work=work, ca=ca)
    register(sys.modules[__name__])
    rc = 0
    try:
        for fn in CASES:
            if only and not fn.cid.startswith(only):
                continue
            try:
                fn()
            except Exception as e:  # a crashing case is a finding about the harness or the target: record it
                verdict(fn.cid, fn.title, False, f"harness exception {type(e).__name__}: {e}", "case completes")
        verdict("Z-ALIVE", "the proxy process survived the whole run and still serves a legitimate request", px.alive()
                and request(connect_line(f"{NAME_A}:443"), timeout=3)[0] == "200", f"alive={px.alive()}", "alive")
    finally:
        px.stop()
        up.stop = True
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} expectations held; {len(failed)} FAILED")
    for r in failed:
        print("  FAIL", r["id"], r["title"], "->", r["observed"])
    if out_json:
        with open(out_json, "w") as f:
            json.dump(RESULTS, f, indent=1)
    return 1 if failed else 0


if __name__ == "__main__":
    if not in_namespace():
        reexec()
    sys.exit(main())
