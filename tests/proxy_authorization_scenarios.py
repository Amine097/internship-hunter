#!/usr/bin/env python3
"""Adversarial CONNECT-proxy scenarios, run INSIDE a throwaway user+network namespace.

tests/test_integration_proxy_authorization.py starts this under `unshare -Urn` (so port 443 can be
bound without root and nothing leaves the machine), and asserts on the JSON it prints. Nothing here
depends on how the proxy is implemented: it speaks HTTP CONNECT and TLS to a proxy on
127.0.0.1:3128 whose only allow-listed host is `localhost`, and a fake upstream on 127.0.0.1:443
records EVERYTHING that reaches it. The security properties are observed at the upstream, not
inferred from the proxy's status line:

  * a denied request must never open a connection to the upstream;
  * a tunnel to an allow-listed host must never carry a TLS ClientHello whose SNI is another
    host, that has no SNI, or that carries Encrypted Client Hello (domain fronting, M-5);
  * an upstream failure must not look like a policy denial (403), and a policy denial must not look
    like an upstream failure (a dead upstream would otherwise pass for "the proxy refused").

Proxy modes: `tinyproxy` (the repo's docker/egress-proxy.sh unchanged, with a real tinyproxy),
`reference` (a hardened in-script proxy that proves the properties are satisfiable),
`reference-no-sni` (the same with the SNI check removed: a mutant the tests must catch) and
`cmd:<shell command>` (any proxy that listens on 3128 and reads EGRESS_ALLOW).
"""

import json
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

PROXY = ("127.0.0.1", 3128)
UPSTREAM_PORT = 443
ALLOWED = os.environ.get("PROXY_ALLOWED_HOST", "localhost")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- TLS ClientHello: build and parse ---------------------------------------------------------
def client_hello(sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def with_extension(hello, ext_type, data):
    """Append one extension to a ClientHello and fix the three enclosing lengths."""
    rec_len = struct.unpack(">H", hello[3:5])[0]
    hs_len = int.from_bytes(hello[6:9], "big")
    p = 9 + 2 + 32  # handshake header, version, random
    p += 1 + hello[p]  # session id
    p += 2 + struct.unpack(">H", hello[p : p + 2])[0]  # cipher suites
    p += 1 + hello[p]  # compression
    ext_len = struct.unpack(">H", hello[p : p + 2])[0]
    ext = struct.pack(">HH", ext_type, len(data)) + data
    body = hello[:p] + struct.pack(">H", ext_len + len(ext)) + hello[p + 2 :] + ext
    body = bytearray(body)
    body[3:5] = struct.pack(">H", rec_len + len(ext))
    body[6:9] = (hs_len + len(ext)).to_bytes(3, "big")
    return bytes(body)


def fragmented(hello, tail=6):
    """The same ClientHello as TWO handshake records, split `tail` bytes before its end, so the
    server_name extension sits entirely in the first record and the whole message only completes
    with the second: a proxy that forwards each record as it inspects it has already sent the
    first one when it can finally judge the SNI."""
    payload = hello[5:]
    cut = len(payload) - tail

    def rec(chunk):
        return b"" + len(chunk).to_bytes(2, "big") + chunk

    return rec(payload[:cut]) + rec(payload[cut:])


def parse_client_hello(data):
    """-> {'sni': str|None, 'ech': bool} or None if `data` does not start with a ClientHello."""
    try:
        if len(data) < 9 or data[0] != 22 or data[5] != 1:
            return None
        p = 9 + 2 + 32
        p += 1 + data[p]
        p += 2 + struct.unpack(">H", data[p : p + 2])[0]
        p += 1 + data[p]
        end = p + 2 + struct.unpack(">H", data[p : p + 2])[0]
        p += 2
        sni, ech = None, False
        while p + 4 <= min(end, len(data)):
            t, ln = struct.unpack(">HH", data[p : p + 4])
            body = data[p + 4 : p + 4 + ln]
            if t == 0 and len(body) >= 5:
                sni = body[5 : 5 + struct.unpack(">H", body[3:5])[0]].decode("ascii", "replace")
            if t == 0xFE0D:
                ech = True
            p += 4 + ln
        return {"sni": sni, "ech": ech}
    except (IndexError, struct.error):
        return None


# ---- the fake upstream: records everything ------------------------------------------------------
class Upstream:
    def __init__(self):
        self.lock = threading.Lock()
        self.connections = []
        self.sock = None
        self.start()

    def start(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", UPSTREAM_PORT))
        self.sock.listen(32)
        threading.Thread(target=self._serve, args=(self.sock,), daemon=True).start()

    def stop(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def reset(self):
        with self.lock:
            self.connections = []

    def snapshot(self):
        with self.lock:
            return [dict(c) for c in self.connections]

    def _serve(self, sock):
        while True:
            try:
                c, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        rec = {"bytes": 0, "hello": None, "first": ""}
        with self.lock:
            self.connections.append(rec)
        c.settimeout(1.0)
        buf = b""
        try:
            while len(buf) < 16384:
                chunk = c.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if parse_client_hello(buf) is not None or not buf.startswith(b"\x16"):
                    break
        except OSError:
            pass
        with self.lock:
            rec["bytes"] = len(buf)
            rec["hello"] = parse_client_hello(buf)
            rec["first"] = buf[:40].decode("latin-1")
        c.close()


# ---- a hardened reference proxy (and a mutant), so the properties are known to be satisfiable ----
def _is_numeric_host(host):
    try:
        socket.inet_aton(host)  # 127.1, 0x7f000001, 0177.0.0.1, 2130706433
        return True
    except OSError:
        return host.replace(".", "").isdigit()


def _deny(c, status=403):
    c.sendall(
        f"HTTP/1.1 {status} Forbidden\r\nX-Egress-Policy: denied\r\n"
        "Content-Length: 0\r\n\r\n".encode()
    )


def _pipe(a, b):
    socks = [a, b]
    while True:
        r, _, _ = select.select(socks, [], [], 5)
        if not r:
            return
        for s in r:
            d = s.recv(65536)
            if not d:
                return
            (b if s is a else a).sendall(d)


def reference_proxy(check_sni):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(PROXY)
    srv.listen(32)

    def handle(c):
        try:
            c.settimeout(5)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 8192:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            head, _, rest = buf.partition(b"\r\n\r\n")
            line = head.split(b"\r\n")[0].decode("latin-1")
            m = re.fullmatch(r"CONNECT ([A-Za-z0-9.-]+):(\d{1,5}) HTTP/1\.[01]", line)
            if not m or m.group(2) != "443":
                return _deny(c)
            host = m.group(1).lower()
            if _is_numeric_host(host) or host != ALLOWED:
                return _deny(c)
            try:
                up = socket.create_connection((host, 443), timeout=3)
            except OSError:
                return _deny(c, 502)
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            first = rest
            while check_sni and parse_client_hello(first) is None and len(first) < 16384:
                if first and not first.startswith(b"\x16"):
                    return
                d = c.recv(4096)
                if not d:
                    return
                first += d
            if check_sni:
                h = parse_client_hello(first)
                if not h or h["ech"] or (h["sni"] or "").lower() != host:
                    return  # SNI absent, different, or hidden by ECH: cut the tunnel unrelayed
            up.sendall(first)
            _pipe(c, up)
        except OSError:
            pass
        finally:
            c.close()

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


# ---- driving a proxy --------------------------------------------------------------------------
def start_proxy(mode):
    env = dict(os.environ, EGRESS_ALLOW=ALLOWED)
    if mode in ("reference", "reference-no-sni"):
        threading.Thread(target=reference_proxy, args=(mode == "reference",), daemon=True).start()
        proc = None
    elif mode == "tinyproxy":
        proc = subprocess.Popen(
            ["sh", os.path.join(ROOT, "docker", "egress-proxy.sh")],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif mode == "egress_proxy":  # docker/egress_proxy.py, resolver pointed at the fake upstream
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "tests", "egress_proxy_loopback_launcher.py")],
            env=dict(env, EGRESS_ALLOW=ALLOWED),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif mode.startswith("cmd:"):
        proc = subprocess.Popen(
            mode[4:], shell=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        sys.exit(f"unknown proxy mode {mode}")
    for _ in range(100):
        try:
            socket.create_connection(PROXY, timeout=0.5).close()
            return proc
        except OSError:
            time.sleep(0.1)
    sys.exit("the proxy under test did not start listening on 127.0.0.1:3128")


def exchange(request, then=None, settle=0.6):
    """Send `request` to the proxy, read its status line, optionally send `then` once tunnelled."""
    s = socket.create_connection(PROXY, timeout=5)
    s.settimeout(1.5)
    status, reply = None, b""
    try:
        s.sendall(request)
        reply = s.recv(4096)
        m = re.match(rb"HTTP/\d\.\d (\d{3})", reply)
        status = int(m.group(1)) if m else None
        if then is not None and status == 200:
            s.sendall(then)
        time.sleep(settle)
    except OSError:
        pass
    finally:
        s.close()
    return status, reply


def connect(authority, version="HTTP/1.1"):
    return f"CONNECT {authority} {version}\r\nHost: {authority}\r\n\r\n".encode()


def run_case(up, name, request, then=None):
    up.reset()
    status, reply = exchange(request, then)
    time.sleep(0.2)
    return {
        "case": name,
        "allowed": ALLOWED,
        "status": status,
        "policy_header": b"x-egress" in reply.lower(),
        "upstream": up.snapshot(),
    }


def main():
    mode = sys.argv[1]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=False)
    up = Upstream()
    proc = start_proxy(mode)
    out = []
    ok = connect(f"{ALLOWED}:443")
    hello = lambda sni: client_hello(sni)  # noqa: E731

    out.append(run_case(up, "legit", ok, hello(ALLOWED)))
    # ---- authorization: nothing but <allowed>:443 may open an upstream connection
    denied = {
        "other_host": connect("example.com:443"),
        "allowed_host_port_80": connect(f"{ALLOWED}:80"),
        "allowed_host_port_8443": connect(f"{ALLOWED}:8443"),
        "allowed_host_port_22": connect(f"{ALLOWED}:22"),
        "ip_literal_loopback": connect("127.0.0.1:443"),
        "ip_decimal": connect("2130706433:443"),
        "ip_hex": connect("0x7f000001:443"),
        "ip_octal": connect("0177.0.0.1:443"),
        "ip_short": connect("127.1:443"),
        "ipv6_mapped_loopback": connect("[::ffff:127.0.0.1]:443"),
        "userinfo_allowed_name_real_ip": connect(f"{ALLOWED}@127.0.0.1:443"),
        "userinfo_garbage_then_allowed": connect(f"evil.example@{ALLOWED}:443"),
        "suffix_lookalike": connect(f"{ALLOWED}.evil.example:443"),
        "prefix_lookalike": connect(f"evil{ALLOWED}:443"),
        "crlf_in_authority": f"CONNECT {ALLOWED}:443\r\nHost: evil.example\r\n\r\n".encode()
        + b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
        "extra_token_in_request_line": f"CONNECT {ALLOWED}:443 HTTP/1.1 evil\r\n\r\n".encode(),
        "absolute_uri_get_to_allowed": (
            f"GET http://{ALLOWED}:443/ HTTP/1.1\r\nHost: {ALLOWED}\r\n\r\n".encode()
        ),
        "origin_form_get": f"GET / HTTP/1.1\r\nHost: {ALLOWED}:443\r\n\r\n".encode(),
        "post_to_allowed": (
            f"POST http://{ALLOWED}:443/ HTTP/1.1\r\nHost: {ALLOWED}\r\nContent-Length: 0\r\n\r\n"
        ).encode(),
    }
    for name, req in denied.items():
        out.append(run_case(up, "deny:" + name, req))
    # ---- domain fronting: allowed CONNECT target, different (or hidden) TLS destination
    out.append(run_case(up, "front:sni_mismatch", ok, hello("evil.example")))
    out.append(run_case(up, "front:sni_absent", ok, hello(None)))
    out.append(run_case(up, "front:sni_mismatch_pipelined", ok + hello("evil.example")))
    out.append(
        run_case(
            up, "front:ech_extension", ok, with_extension(hello(ALLOWED), 0xFE0D, b"\x00" * 40)
        )
    )
    out.append(run_case(up, "front:fragmented_sni_first", ok, fragmented(hello("evil.example"))))
    out.append(run_case(up, "front:fragmented_pipelined", ok + fragmented(hello("evil.example"))))
    # ---- failure semantics: a dead upstream is an upstream failure, not a policy decision
    up.stop()
    time.sleep(0.2)
    out.append(run_case(up, "upstream_down", ok, hello(ALLOWED)))
    up.start()
    # ---- survival: after all that, the proxy still serves the legitimate request
    out.append(run_case(up, "legit_after", ok, hello(ALLOWED)))

    print("SCENARIOS " + json.dumps(out))
    sys.stdout.flush()
    if proc:
        proc.terminate()
    os._exit(0)


if __name__ == "__main__":
    main()
