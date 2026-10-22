"""The attack cases (see harness.py for the environment). Each case states what a SAFE proxy must do and
asserts it against ground truth: the bytes and connections the "provider" actually received, the proxy's
own audit log, and what the client observed. Cases marked INFO document a residual the proxy cannot close."""
from __future__ import annotations

import os
import socket
import ssl
import subprocess
import threading
import time


def register(h):  # noqa: C901 - one flat list of cases is the point
    case, verdict, CTX = h.case, h.verdict, h.CTX
    A, B = h.NAME_A, h.NAME_B

    def up():
        return CTX["up"]

    def px():
        return CTX["px"]

    # ------------------------------------------------------------------------------------ helpers
    def refused(cid, title, raw, statuses=("400", "403"), reasons=None, timeout=3):
        @case(cid, title)
        def _():
            mark, pm = up().mark(), px().mark()
            st, rs, _head = h.request(raw, timeout=timeout)
            conns = up().since(mark)
            ok = st in statuses and (reasons is None or rs in reasons) and not conns
            verdict(cid, title, ok, f"status={st or '-'} reason={rs or '-'} upstream_connections={len(conns)}",
                    f"{'/'.join(statuses)}{' '+'/'.join(reasons) if reasons else ''}, no upstream connection")
        return _

    def line(target, ver="HTTP/1.1", method="CONNECT", extra=""):
        return f"{method} {target} {ver}\r\nHost: x\r\n{extra}\r\n".encode("latin-1", "replace")

    # ================================================================================ HTTP layer
    refused("H01", "CONNECT to an unlisted host", line("example.com:443"), ("403",), ("host",))
    for n, t in enumerate(["93.184.216.34:443", "1572395042:443", "0x5db8d822:443", "0135.0270.0330.042:443",
                           "93.184.55330:443", "[::1]:443", "[::ffff:93.184.216.34]:443", "[2001:db8::1]:443",
                           "127.1:443", "0:443", "localhost:443"], 2):
        refused(f"H02.{n:02d}", f"IP literal / numeric forms / v6: {t}", line(t), ("403",), ("host",))
    for n, t in enumerate([f"user@{A}:443", f"{A}:443@evil.test:443", f"evil.test:443@{A}:443",
                           f"{A}@evil.test:443", f"evil.test@{A}:443"], 1):
        refused(f"H03.{n:02d}", f"userinfo / authority confusion: {t}", line(t), ("403",), ("host", "port"))
    refused("H04", "trailing-dot FQDN of an allowed host", line(f"{A}.:443"), ("403",), ("host",))
    refused("H05", "allowed name as a suffix of another name", line(f"evil.{A}:443"), ("403",), ("host",))
    refused("H05b", "allowed name as a prefix of another name", line(f"{A}.evil.test:443"), ("403",), ("host",))
    for n, port in enumerate(["80", "8443", "0443", "443.0", "+443", "00443", "65536", "", "443:443", "-1", "0x1bb"], 1):
        refused(f"H06.{n:02d}", f"port {port!r}", line(f"{A}:{port}"), ("403", "400"), ("port", "host", "malformed"))
    refused("H06.12", "no port at all", line(A), ("403", "400"), ("port", "host", "malformed"))
    refused("H06.13", "port with a path", line(f"{A}:443/x"), ("403",), ("port",))
    for n, (m, t) in enumerate([("GET", f"http://{A}/"), ("POST", f"http://{A}/"), ("GET", f"/{A}"),
                                ("OPTIONS", "*"), ("connect", f"{A}:443"), ("HEAD", f"http://{A}/"),
                                ("TRACE", f"http://{A}/"), ("CONNECT ", f"{A}:443"), ("PRI", "*")], 1):
        refused(f"H07.{n:02d}", f"method {m!r} {t}", line(t, method=m), ("403", "400"), ("method", "malformed"))
    refused("H07.10", "HTTP/2 connection preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", ("403", "400"), ("method", "malformed"))
    for n, v in enumerate(["HTTP/0.9", "HTTP/2.0", "HTTP/1.2", "http/1.1", "HTTP/1.1 ", "HTTP/1.", ""], 1):
        refused(f"H08.{n:02d}", f"protocol version {v!r}", f"CONNECT {A}:443 {v}\r\nHost: x\r\n\r\n".encode(),
                ("400",), ("malformed",))
    refused("H08.08", "HTTP/0.9 style (no version)", f"CONNECT {A}:443\r\n\r\n".encode(), ("400",), ("malformed",))
    for n, t in enumerate(["%61pi.provider-a.test:443", f"{A}\x00.evil.test:443", f"{A}\x0b:443", f"{A}\x7f:443",
                           f"{A}\t:443", f"\x00{A}:443", f"{A}%00:443", f"{A}é:443"], 1):
        refused(f"H09.{n:02d}", f"control / encoded characters in the target: {t!r}",
                line(t) if t.isascii() else (f"CONNECT {t} HTTP/1.1\r\nHost: x\r\n\r\n").encode("utf-8"),
                ("403", "400"), ("host", "port", "malformed", "non-ascii"))
    refused("H10", "obsolete line folding in a header", f"CONNECT {A}:443 HTTP/1.1\r\nX: a\r\n b: c\r\n\r\n".encode(),
            ("400",), ("malformed",))
    refused("H11", "header line without a colon", f"CONNECT {A}:443 HTTP/1.1\r\nbroken\r\n\r\n".encode(), ("400",), ("malformed",))
    refused("H12", "65 headers (limit 64)", (f"CONNECT {A}:443 HTTP/1.1\r\n" + "".join(f"H{i}: v\r\n" for i in range(65))
                                           + "\r\n").encode(), ("400",), ("malformed",))
    refused("H13", "request head over 8 KiB", (f"CONNECT {A}:443 HTTP/1.1\r\nX: " + "a" * 9000 + "\r\n\r\n").encode(),
            ("400",), ("head-too-large",))
    refused("H14", "request LINE over 8 KiB", (f"CONNECT {A}:443" + "9" * 9000 + " HTTP/1.1\r\n\r\n").encode(),
            ("400", "403"), ("head-too-large", "port"))
    refused("H15", "absolute-form target", line(f"https://{A}:443/"), ("403",), ("host", "port"))
    refused("H16", "bare CR inside the request line", f"CONNECT {A}:443\rX HTTP/1.1\r\n\r\n".encode(), ("400",), ("malformed",))
    refused("H17", "bare LF inside a header", f"CONNECT {A}:443 HTTP/1.1\r\nX: a\nGET / HTTP/1.1\r\n\r\n".encode(),
            ("400",), ("malformed",))
    refused("H17b", "non-ASCII bytes in a header", f"CONNECT {A}:443 HTTP/1.1\r\nX: ".encode() + b"\xff\xfe\r\n\r\n",
            ("400",), ("non-ascii",))
    refused("H17c", "NUL byte in the request line", f"CONNECT {A}:443 HTTP/1.1\x00\r\n\r\n".encode(), ("400",), ("malformed",))
    refused("H17d", "two spaces between tokens", f"CONNECT  {A}:443 HTTP/1.1\r\n\r\n".encode(), ("400",), ("malformed",))
    refused("H17e", "tab as separator", f"CONNECT\t{A}:443\tHTTP/1.1\r\n\r\n".encode(), ("400",), ("malformed",))

    @case("H18", "an allowed CONNECT is accepted (positive control), in every case and with proxy headers")
    def _():
        res = []
        for tgt, extra in [(f"{A}:443", ""), (f"{A.upper()}:443", ""), (f"{A}:443", "Proxy-Authorization: Basic eDp5\r\nVia: 1.1 x\r\nX-Forwarded-For: 1.2.3.4\r\n"),
                           (f"{B}:443", "")]:
            res.append(h.request(line(tgt, extra=extra), timeout=2)[0])
        verdict("H18", "allowed CONNECT is accepted", res == ["200"] * 4, str(res), "200 x4")

    def after_connect(cid, title, tail, reason, hold=False):
        @case(cid, title)
        def _():
            mark, pm = up().mark(), px().mark()
            s = h.connect()
            s.sendall(h.connect_line(f"{A}:443") + tail)
            data, closed = h.drain(s, 2.0)
            s.close()
            conns = up().since(mark)
            logs = px().since(pm)
            got = [r.get("reason") for r in logs]
            ok = data.startswith(b"HTTP/1.1 200") and reason in got and sum(len(c.data) for c in conns) == 0
            verdict(cid, title, ok, f"reply={data[:40]!r} reasons={got} upstream_bytes={sum(len(c.data) for c in conns)}",
                    f"200 then cut ({reason}), 0 bytes upstream")
        return _

    after_connect("H19", "request smuggled in the same segment as the CONNECT (pipelined GET)",
                  b"GET /secret HTTP/1.1\r\nHost: evil.test\r\n\r\n", "tls-not-tls")
    after_connect("H20", "second CONNECT pipelined behind the first", h.connect_line("evil.test:443"), "tls-not-tls")

    @case("H21", "CONNECT head declaring a Content-Length body that is an HTTP request")
    def _():
        mark, pm = up().mark(), px().mark()
        body = b"GET /x HTTP/1.1\r\nHost: evil.test\r\n\r\n"
        s = h.connect()
        s.sendall(f"CONNECT {A}:443 HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        data, closed = h.drain(s, 2.0)
        s.close()
        n = h.up_none(mark) and True
        logs = [r.get("reason") for r in px().since(pm)]
        verdict("H21", "Content-Length body is treated as tunnel bytes and cut", data.startswith(b"HTTP/1.1 200") and "tls-not-tls" in logs and n,
                f"reasons={logs}", "cut, 0 bytes upstream")

    @case("H22", "head truncated by EOF / sent one byte at a time: no crash, no upstream connection")
    def _():
        mark = up().mark()
        s = h.connect()
        s.sendall(f"CONNECT {A}:44".encode())
        s.close()
        s = h.connect()
        for ch in f"CONNECT {A}:443 HTTP/1.1\r\n".encode():
            s.sendall(bytes([ch]))
            time.sleep(0.01)
        s.close()
        time.sleep(0.5)
        verdict("H22", "partial heads", px().alive() and not up().since(mark), f"alive={px().alive()}", "alive, no upstream")

    @case("H23", "an LF-only terminated head never completes: the connection is dropped after the head timeout (~10s), nothing upstream")
    def _():
        mark, pm = up().mark(), px().mark()
        s = h.connect()
        s.sendall(f"CONNECT {A}:443 HTTP/1.1\nHost: x\n\n".encode())
        t0 = time.monotonic()
        data, closed = h.drain(s, 14.0)
        dt = time.monotonic() - t0
        s.close()
        logs = px().since(pm)
        verdict("H23", "LF-only head", closed and not up().since(mark) and 8 < dt < 13,
                f"closed={closed} after {dt:.1f}s data={data[:30]!r} log={[r.get('verdict') for r in logs]}",
                "closed after ~10 s, no upstream connection")

    # ================================================================================ DNS / addresses
    rebinding = {
        "priv10.provider.test": "10.9.9.9", "priv172.provider.test": "172.31.9.9", "priv192.provider.test": "192.168.9.9",
        "loop.provider.test": "127.0.0.2", "linklocal.provider.test": "169.254.169.254",
        "cgnat.provider.test": "100.100.100.100", "cgnat2.provider.test": "100.64.1.1",
        "zero.provider.test": "0.0.0.0", "bcast.provider.test": "255.255.255.255",
        "multicast.provider.test": "224.0.0.251", "classe.provider.test": "240.0.0.1",
        "bench.provider.test": "198.18.0.7", "doc.provider.test": "203.0.113.5", "ietf.provider.test": "192.0.0.1",
    }
    for i, (name, addr) in enumerate(rebinding.items(), 1):
        refused(f"D01.{i:02d}", f"allowed name resolving to {addr} is refused without dialling",
                line(f"{name}:443"), ("403",), ("resolve-non-global",))

    @case("D02", "mixed answers (global + private, both orders) are refused as a whole; the global address is NOT dialled")
    def _():
        out = []
        for name in ("mixed1.provider.test", "mixed2.provider.test"):
            mark = up().mark()
            st, rs, _ = h.request(line(f"{name}:443"))
            out.append((name, st, rs, len(up().since(mark))))
        ok = all(o[1] == "403" and o[2] == "resolve-non-global" and o[3] == 0 for o in out)
        verdict("D02", "mixed answers", ok, str(out), "403 resolve-non-global, 0 connections")

    @case("D03", "IPv6-only and IPv4-mapped answers cannot be dialled (no AAAA path, no mapped bypass)")
    def _():
        out = []
        for name in ("v6only.provider.test", "v6mapped.provider.test"):
            mark = up().mark()
            st, rs, _ = h.request(line(f"{name}:443"), timeout=4)
            out.append((name, st, rs, len(up().since(mark))))
        ok = all(o[1] in ("502", "403") and o[3] == 0 for o in out)
        verdict("D03", "v6-only / v4-mapped", ok, str(out), "403 or 502, 0 connections")

    @case("D04", "an unresolvable allowed name is a TRANSPORT failure (502), not a policy denial (403), and does not hang")
    def _():
        t0 = time.monotonic()
        st, rs, _ = h.request(line("nxdomain.provider.test:443"), timeout=15)
        dt = time.monotonic() - t0
        verdict("D04", "DNS failure classification", st == "502" and rs == "resolve-failed" and dt < 12,
                f"status={st} reason={rs} in {dt:.1f}s", "502 resolve-failed quickly")

    @case("D05", "DNS rebinding between two requests: the first answer is not cached, the second is judged afresh")
    def _():
        name = "flip.provider.test"
        first = h.request(line(f"{name}:443"))[0]
        h.rewrite_hosts(CTX["work"], name, ["10.9.9.9"])
        mark = up().mark()
        second = h.request(line(f"{name}:443"))
        h.rewrite_hosts(CTX["work"], name, [h.PROVIDER_A, "10.9.9.9"])
        third = h.request(line(f"{name}:443"))
        h.rewrite_hosts(CTX["work"], name, [h.PROVIDER_A])
        fourth = h.request(line(f"{name}:443"))[0]
        conns = up().since(mark)
        ok = (first == "200" and second[:2] == ("403", "resolve-non-global") and third[:2] == ("403", "resolve-non-global")
              and fourth == "200" and all(c.address == h.PROVIDER_A for c in conns))
        verdict("D05", "rebinding", ok, f"{first} {second[:2]} {third[:2]} {fourth}; dialled={[c.address for c in conns]}",
                "200, 403, 403, 200 and never a private address")

    @case("D06", "the proxy dials exactly the address it validated (audit record agrees with the provider's accept log)")
    def _():
        mark, pm = up().mark(), px().mark()
        s = h.tunnel(A)
        s.close()
        conns, logs = up().since(mark), px().since(pm)
        rec = [r for r in logs if r.get("host") == A]
        ok = conns and rec and rec[-1].get("upstream") == h.PROVIDER_A == conns[0].address and rec[-1].get("addresses") == [h.PROVIDER_A]
        verdict("D06", "dialled == validated", bool(ok), f"log={rec[-1] if rec else None}", "upstream == addresses == 93.184.216.34")

    # ================================================================================ TLS gate
    def tls_attack(cid, title, payload_chunks, reasons, *, host=A, max_up=0, delay=0.0, wait=2.0, expect_cut=True,
                   script=None, post=None):
        """Open a tunnel to `host`, send chunks, and assert on what the provider got and why the proxy cut."""
        @case(cid, title)
        def _():
            if script:
                up().script[h.PROVIDER_A] = script
            try:
                mark, pm = up().mark(), px().mark()
                s = h.tunnel(host)
                for chunk in payload_chunks() if callable(payload_chunks) else payload_chunks:
                    try:
                        s.sendall(chunk)
                    except OSError:
                        break
                    if delay:
                        time.sleep(delay)
                data, closed = h.drain(s, wait)
                s.close()
                conns = up().since(mark)
                logs = px().since(pm)
                got = [r.get("reason") for r in logs if r.get("verdict") == "cut"]
                nbytes = sum(len(c.data) for c in conns)
                ok = nbytes <= max_up and (not expect_cut or closed) and (not reasons or any(g in reasons for g in got))
                if post:
                    ok = ok and post(conns, data, logs)
                verdict(cid, title, ok, f"cut_reasons={got} upstream_bytes={nbytes} closed_by_proxy={closed}",
                        f"cut ({'/'.join(reasons) if reasons else 'any'}), upstream bytes <= {max_up}")
            finally:
                up().script.pop(h.PROVIDER_A, None)
        return _

    ch = h.client_hello
    rec = h.record

    # -- the server name
    tls_attack("T01", "SNI of another site", [rec(22, ch(b"evil.example.test"))], ("tls-sni-mismatch",))
    tls_attack("T02", "SNI of ANOTHER ALLOW-LISTED host (CONNECT a, SNI b)", [rec(22, ch(B.encode()))], ("tls-sni-mismatch",))
    tls_attack("T03", "no server_name extension", [rec(22, ch(None))], ("tls-no-sni",))
    tls_attack("T04", "no extensions at all", [rec(22, ch(None, no_exts=True))], ("tls-no-sni",))
    tls_attack("T05", "SNI with a trailing dot", [rec(22, ch((A + ".").encode()))], ("tls-sni-mismatch",))
    tls_attack("T06", "SNI = allowed name + NUL + junk", [rec(22, ch((A + "\x00.evil.test").encode()))], ("tls-sni-mismatch",))
    tls_attack("T07", "SNI = allowed name as a prefix (extra label)", [rec(22, ch((A + ".evil.test").encode()))], ("tls-sni-mismatch",))
    tls_attack("T08", "SNI = IP literal of the provider", [rec(22, ch(h.PROVIDER_A.encode()))], ("tls-sni-mismatch",))
    tls_attack("T09", "two host_name entries in server_name (first allowed, second evil)",
               [rec(22, ch(sni_exts=[h.ext(0, (lambda l: len(l).to_bytes(2, 'big') + l)(
                   b"\x00" + len(A).to_bytes(2, 'big') + A.encode() + b"\x00" + len(b"evil.test").to_bytes(2, 'big') + b"evil.test"))]))],
               ("tls-sni-list",))
    tls_attack("T10", "two host_name entries (evil first, allowed second)",
               [rec(22, ch(sni_exts=[h.ext(0, (lambda l: len(l).to_bytes(2, 'big') + l)(
                   b"\x00" + len(b"evil.test").to_bytes(2, 'big') + b"evil.test" + b"\x00" + len(A).to_bytes(2, 'big') + A.encode()))]))],
               ("tls-sni-list",))
    tls_attack("T11", "server_name entry with an unknown name_type", [rec(22, ch(sni_exts=[h.sni_ext(A.encode(), kind=1)]))],
               ("tls-sni-list",))
    tls_attack("T12", "duplicate server_name extensions (allowed, evil)",
               [rec(22, ch(sni_exts=[h.sni_ext(A.encode()), h.sni_ext(b"evil.test")]))], ("tls-malformed",))
    tls_attack("T13", "duplicate server_name extensions (evil, allowed)",
               [rec(22, ch(sni_exts=[h.sni_ext(b"evil.test"), h.sni_ext(A.encode())]))], ("tls-malformed",))
    tls_attack("T14", "non-ASCII server name", [rec(22, ch("api.provider-a.tést".encode()))], ("tls-sni-invalid", "tls-sni-mismatch"))
    tls_attack("T15", "valid SNI plus an Encrypted Client Hello extension (0xfe0d)",
               [rec(22, ch(A.encode(), exts_extra=[h.ext(0xFE0D, b"\x00" * 64)]))], ("tls-ech",))
    tls_attack("T16", "valid SNI plus the old ESNI extension (0xffce)", [rec(22, ch(A.encode(), exts_extra=[h.ext(0xFFCE, b"\x00" * 32)]))],
               ("tls-ech",))
    tls_attack("T17", "evil SNI hidden behind an ECH GREASE-looking extension", [rec(22, ch(b"evil.test", exts_extra=[h.ext(0xFE0D, b"\x00" * 8)]))],
               ("tls-ech", "tls-sni-mismatch"))

    # -- malformed structure
    tls_attack("T20", "session_id longer than 32 bytes", [rec(22, ch(A.encode(), session_id=b"x" * 33))], ("tls-malformed",))
    tls_attack("T21", "odd-length cipher_suites", [rec(22, ch(A.encode(), suites=b"\x13\x01\x13"))], ("tls-malformed",))
    tls_attack("T22", "empty compression_methods", [rec(22, ch(A.encode(), compression=b""))], ("tls-malformed",))
    tls_attack("T23", "bytes after the extensions block", [rec(22, ch(A.encode(), tail=b"\x00\x00"))], ("tls-malformed",))
    tls_attack("T24", "extension length overruns the hello", [rec(22, ch(raw_exts=b"\x00\x00\xff\xff" + b"\x00" * 4))], ("tls-malformed",))
    tls_attack("T25", "server_name length field larger than its data",
               [rec(22, ch(raw_exts=h.ext(0, b"\x00\x30\x00\x00\x20" + A.encode())))], ("tls-malformed",))
    tls_attack("T26", "hello truncated inside the random", [rec(22, h.hs(1, b"\x03\x03" + b"\x00" * 10))], ("tls-malformed",))
    tls_attack("T27", "handshake header declaring 16 MiB", [rec(22, b"\x01\xff\xff\xff" + b"\x00" * 40)], ("tls-malformed",))
    tls_attack("T28", "handshake header declaring exactly 65537 bytes", [rec(22, b"\x01\x01\x00\x01" + b"\x00" * 40)], ("tls-malformed",))
    tls_attack("T29", "record length above the TLS maximum", [b"\x16\x03\x03\xff\xff" + b"\x00" * 100], ("tls-malformed",))
    tls_attack("T30", "record version major != 3 (SSLv2-style hello)", [b"\x80\x2e\x01\x03\x01" + b"\x00" * 60], ("tls-not-tls",))
    tls_attack("T31", "plain HTTP inside the tunnel", [b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n"], ("tls-not-tls",))
    tls_attack("T32", "first record is ChangeCipherSpec", [rec(20, b"\x01"), rec(22, ch(A.encode()))], ("tls-not-handshake",))
    tls_attack("T33", "first record is an alert", [rec(21, b"\x01\x00"), rec(22, ch(A.encode()))], ("tls-not-handshake",))
    tls_attack("T34", "first record is application data", [rec(23, b"x" * 50), rec(22, ch(A.encode()))], ("tls-not-handshake",))
    tls_attack("T35", "first record is a heartbeat", [rec(24, b"x" * 50)], ("tls-not-tls", "tls-record-type", "tls-not-handshake"))
    tls_attack("T36", "empty handshake record then an evil hello", [rec(22, b""), rec(22, ch(b"evil.test"))],
               ("tls-sni-mismatch", "tls-empty-fragment"))
    tls_attack("T37", "TLS 1.3 compat CCS before the hello", [rec(20, b"\x01"), rec(22, ch(b"evil.test"))], ("tls-not-handshake",))

    # -- fragmentation: nothing may reach the provider until the WHOLE hello was judged
    evil = ch(b"evil.example.test")
    good = ch(A.encode())
    for n, size in enumerate([1, 2, 3, 5, 7, 16, 37, 64], 1):
        tls_attack(f"F0{n}", f"evil hello split into {size}-byte handshake fragments (one record each)",
                   [rec(22, p) for p in h.fragment(evil, [size])], ("tls-sni-mismatch",))
    tls_attack("F09", "evil hello: header alone, then the body in one record",
               [rec(22, evil[:4]), rec(22, evil[4:])], ("tls-sni-mismatch",))
    tls_attack("F10", "evil hello: the SNI is in the LAST 1-byte record (first records look harmless)",
               [rec(22, p) for p in h.fragment(evil, [1])], ("tls-sni-mismatch",))
    tls_attack("F11", "allowed hello + a 3-byte partial header of a second message, then an evil ClientHello",
               [rec(22, good + evil[:3]), rec(22, evil[3:])], ("tls-sni-mismatch", "tls-malformed", "tls-extra-client-hello"))
    tls_attack("F12", "allowed hello + 2 bytes of a second message, then silence: the first hello must stay HELD",
               [rec(22, good + b"\x01\x00")], (), max_up=0, wait=1.0, expect_cut=False)
    tls_attack("F13", "evil hello fragment, then ChangeCipherSpec (record types interleaved inside a handshake message)",
               [rec(22, evil[:20]), rec(20, b"\x01"), rec(22, evil[20:])], ("tls-interleaved",))
    tls_attack("F14", "evil hello fragment, then an alert", [rec(22, evil[:20]), rec(21, b"\x01\x00")], ("tls-interleaved",))
    tls_attack("F15", "evil hello fragment, then application data", [rec(22, evil[:20]), rec(23, b"x" * 30)], ("tls-interleaved",))
    tls_attack("F16", "all fragments pipelined in ONE segment (evil)", lambda: [b"".join(rec(22, p) for p in h.fragment(evil, [11]))],
               ("tls-sni-mismatch",))
    @case("F17", "CONNECT head + fragmented evil hello in a SINGLE write: nothing reaches the provider")
    def _():
        mark, pm = up().mark(), px().mark()
        s = h.connect()
        s.sendall(h.connect_line(f"{A}:443") + b"".join(rec(22, p) for p in h.fragment(evil, [9])))
        data, closed = h.drain(s, 2.0)
        s.close()
        n = sum(len(c.data) for c in up().since(mark))
        got = [r.get("reason") for r in px().since(pm)]
        verdict("F17", "single-write CONNECT + fragmented evil hello", n == 0 and "tls-sni-mismatch" in got, f"upstream_bytes={n} reasons={got}",
                "0 bytes upstream, tls-sni-mismatch")
    @case("F18", "valid hello fragmented into 1-byte records still reaches the provider (compatibility, positive control)")
    def _():
        mark = up().mark()
        s = h.tunnel(A)
        for p in h.fragment(good, [1]):
            s.sendall(rec(22, p))
        time.sleep(0.8)
        s.close()
        conns = up().since(mark)
        want = b"".join(rec(22, p) for p in h.fragment(good, [1]))
        verdict("F18", "fragmented valid hello is delivered intact", conns and conns[0].data == want,
                f"upstream_bytes={sum(len(c.data) for c in conns)} want={len(want)}", "the exact fragmented bytes")

    @case("F19", "the provider receives the allowed hello BYTE FOR BYTE (no rewriting) and nothing before it is complete")
    def _():
        mark = up().mark()
        s = h.tunnel(A)
        recs = [rec(22, p) for p in h.fragment(good, [40])]
        for r in recs[:-1]:
            s.sendall(r)
            time.sleep(0.15)
            seen = sum(len(c.data) for c in up().since(mark))
            if seen:
                s.close()
                verdict("F19", "no early release", False, f"provider received {seen} bytes before the hello was complete",
                        "0 bytes until the last fragment")
                return
        s.sendall(recs[-1])
        time.sleep(0.5)
        s.close()
        got = b"".join(c.data for c in up().since(mark))
        verdict("F19", "held until complete, then released unchanged", got == b"".join(recs), f"{len(got)}/{sum(map(len, recs))}",
                "full hello delivered after the last fragment")

    # -- more than one hello, retries, post-hello behaviour (scripted provider)
    def reader_script(replies):
        """Provider that reads records and answers with `replies[i]` after the i-th record arrives."""
        def script(conn, sock):
            sent = 0
            while True:
                try:
                    data = sock.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                conn.chunks.append(data)
                while sent < len(replies) and replies[sent][0] <= len(conn.chunks):
                    try:
                        sock.sendall(replies[sent][1])
                    except OSError:
                        return
                    sent += 1
        return script

    tls_attack("R01", "second ClientHello (allowed SNI) without a HelloRetryRequest", [rec(22, good), rec(22, good)],
               ("tls-extra-client-hello",), max_up=len(rec(22, good)) + 5, wait=1.5)
    tls_attack("R02", "second ClientHello (evil SNI) without a HelloRetryRequest", [rec(22, good), rec(22, evil)],
               ("tls-sni-mismatch",), max_up=len(rec(22, good)) + 5, wait=1.5)

    def hello_len(sni):
        return len(rec(22, ch(sni)))

    @case("R03", "after a HelloRetryRequest a second hello with an EVIL SNI is cut and never forwarded; one with the right SNI passes")
    def _():
        up().script[h.PROVIDER_A] = reader_script([(1, h.server_hello(hrr=True))])
        try:
            mark, pm = up().mark(), px().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good))
            d1, _ = h.drain(s, 0.8)
            s.sendall(rec(22, evil))
            d2, closed = h.drain(s, 1.5)
            s.close()
            conns = up().since(mark)
            got = [r.get("reason") for r in px().since(pm)]
            evil_seen = b"evil.example.test" in b"".join(c.data for c in conns)
            ok = d1 == h.server_hello(hrr=True) and closed and "tls-sni-mismatch" in got and not evil_seen
            verdict("R03a", "HRR then evil second hello", ok, f"hrr_forwarded={d1 == h.server_hello(hrr=True)} reasons={got} evil_reached_provider={evil_seen}",
                    "HRR delivered to client, evil hello cut, never forwarded")
            mark = up().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good))
            h.drain(s, 0.8)
            s.sendall(rec(22, ch(A.encode())))
            time.sleep(0.8)
            s.close()
            seen = sum(len(c.data) for c in up().since(mark))
            verdict("R03b", "HRR then correct second hello is forwarded", seen == 2 * len(rec(22, good)) or seen > len(rec(22, good)), f"upstream_bytes={seen}", "both hellos forwarded")
        finally:
            up().script.pop(h.PROVIDER_A, None)

    @case("R04", "second HelloRetryRequest and a hello after the ServerHello are cut")
    def _():
        up().script[h.PROVIDER_A] = reader_script([(1, h.server_hello(hrr=True)), (2, h.server_hello(hrr=True))])
        try:
            pm = px().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good)); h.drain(s, 0.6)
            s.sendall(rec(22, good))
            d, closed = h.drain(s, 1.5)
            s.close()
            got = [r.get("reason") for r in px().since(pm)]
            verdict("R04a", "two HRRs", closed and "tls-second-retry" in got, f"reasons={got}", "tls-second-retry")
        finally:
            up().script.pop(h.PROVIDER_A, None)
        up().script[h.PROVIDER_A] = reader_script([(1, h.server_hello())])
        try:
            mark, pm = up().mark(), px().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good)); h.drain(s, 0.6)
            s.sendall(rec(22, evil))
            d, closed = h.drain(s, 1.5)
            s.close()
            got = [r.get("reason") for r in px().since(pm)]
            seen_evil = b"evil.example.test" in b"".join(c.data for c in up().since(mark))
            verdict("R04b", "plaintext ClientHello (evil SNI) AFTER the ServerHello", closed and "tls-client-hello-after-server-hello" in got and not seen_evil,
                    f"reasons={got} evil_forwarded={seen_evil}", "cut, not forwarded")
        finally:
            up().script.pop(h.PROVIDER_A, None)

    @case("R05", "INFO residual: after the ServerHello a ChangeCipherSpec switches the tunnel to raw; a plaintext hello behind it is forwarded unjudged")
    def _():
        up().script[h.PROVIDER_A] = reader_script([(1, h.server_hello())])
        try:
            mark, pm = up().mark(), px().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good)); h.drain(s, 0.6)
            s.sendall(rec(20, b"\x01") + rec(22, evil))
            time.sleep(0.8)
            s.close()
            seen_evil = b"evil.example.test" in b"".join(c.data for c in up().since(mark))
            verdict("R05", "CCS then plaintext evil hello after ServerHello", True,
                    f"evil_forwarded_to_provider={seen_evil}",
                    "INFO: forwarded (documented as a residual): a real TLS peer treats it as a protocol error; encrypted TLS1.2 renegotiation is equally invisible",
                    note="not a policy bypass on its own: the provider decides what a plaintext handshake record after its ServerHello means")
        finally:
            up().script.pop(h.PROVIDER_A, None)

    @case("R06", "server speaks first with something that is not a ServerHello: cut, nothing relayed to the client")
    def _():
        up().script[h.PROVIDER_A] = lambda conn, sock: (sock.recv(10), sock.sendall(b"HTTP/1.1 200 OK\r\n\r\nsecret"))
        try:
            pm = px().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good))
            d, closed = h.drain(s, 1.5)
            s.close()
            got = [r.get("reason") for r in px().since(pm)]
            verdict("R06", "plain HTTP from the provider side", b"secret" not in d and closed and "tls-not-tls" in got, f"client_got={d[:30]!r} reasons={got}",
                    "cut, no plaintext relayed")
        finally:
            up().script.pop(h.PROVIDER_A, None)

    @case("R07", "server flood before its ServerHello is cut at the budget (256 KiB), client never receives more than that")
    def _():
        def flood(conn, sock):
            conn.chunks.append(sock.recv(65536))         # drain the hello: closing with unread data sends an RST that races the flood
            try:
                for _ in range(200):
                    sock.sendall(h.record(21, b"\x01\x00") * 400)
                time.sleep(2)                           # keep the socket open until the proxy has cut
            except OSError:
                pass
        up().script[h.PROVIDER_A] = flood
        try:
            pm = px().mark()
            s = h.tunnel(A)
            s.sendall(rec(22, good))
            d, closed = h.drain(s, 3.0)
            s.close()
            recs = px().since(pm)
            got = [r.get("reason") for r in recs]
            verdict("R07", "server-side flood", closed and "tls-inspect-budget" in got and len(d) < (1 << 18) + 4096, f"client_got={len(d)} records={recs}",
                    "tls-inspect-budget, <= ~256 KiB relayed")
        finally:
            up().script.pop(h.PROVIDER_A, None)

    # -- budgets, memory, concurrency
    @case("B01", "client flood of application-data records after a valid hello is cut at the 1 MiB inspection budget")
    def _():
        mark, pm = up().mark(), px().mark()
        s = h.tunnel(A)
        s.sendall(rec(22, good))
        junk = rec(23, b"z" * 16000)
        sent = 0
        try:
            for _ in range(200):
                s.sendall(junk)
                sent += len(junk)
        except OSError:
            pass
        d, closed = h.drain(s, 1.5)
        s.close()
        n = sum(len(c.data) for c in up().since(mark))
        got = [r.get("reason") for r in px().since(pm)]
        verdict("B01", "pre-ServerHello opaque data budget", "tls-inspect-budget" in got and n <= (1 << 20) + 20000, f"sent={sent} provider_got={n} reasons={got}",
                "cut at ~1 MiB; the provider cannot be fed more")

    @case("B02", "memory/CPU: a 65 KB hello trickled in 1-byte records (6 bytes on the wire each) is held, bounded, and judged")
    def _():
        before, fds0 = px().rss_kb(), px().fds()
        pm = px().mark()
        s = h.tunnel(A)
        t0 = time.monotonic()
        s.sendall(rec(22, b"\x01\x00\xff\xff"))
        piece = rec(22, b"A")
        try:
            for _ in range(70000):
                s.sendall(piece)
        except OSError:
            pass
        d, closed = h.drain(s, 3.0)
        dt = time.monotonic() - t0
        s.close()
        after = px().rss_kb()
        got = [r.get("reason") for r in px().since(pm)]
        up_bytes = sum(len(c.data) for c in up().conns[-1:])
        verdict("B02", "held-record memory", closed and after - before < 40000 and px().fds() <= fds0 + 2 and up_bytes == 0,
                f"rss {before}->{after} kB, reasons={got}, {dt:.1f}s, provider_bytes={up_bytes}, fds {fds0}->{px().fds()}",
                "cut, RSS growth < 40 MB, nothing upstream, no fd leak")

    @case("B07", "16 concurrent hostile clients (tiny-record floods) against the 64 MiB / 0.25 CPU container budget: peak RSS and time")
    def _():
        base = px().rss_kb()
        peak = [base]
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], px().rss_kb())
                time.sleep(0.05)
        threading.Thread(target=sample, daemon=True).start()
        results = []

        def attack():
            try:
                s = h.tunnel(A)
                s.sendall(rec(22, b"\x01\x00\xff\xff"))
                piece = rec(22, b"A") * 100
                for _ in range(700):
                    s.sendall(piece)
                results.append("sent")
                s.close()
            except OSError as e:
                results.append(type(e).__name__)
        t0 = time.monotonic()
        ths = [threading.Thread(target=attack) for _ in range(16)]
        [t.start() for t in ths]
        [t.join(60) for t in ths]
        dt = time.monotonic() - t0
        stop.set()
        time.sleep(0.5)
        alive = px().alive()
        ok_after = h.request(h.connect_line(f"{A}:443"))[0]
        verdict("B07", "concurrent flood", alive and peak[0] - base < 40000 and ok_after == "200",
                f"peak RSS {base}->{peak[0]} kB (+{(peak[0] - base) // 1024} MiB) in {dt:.1f}s, alive={alive}, after: {ok_after}",
                "alive; growth well inside 64 MiB; serving afterwards")

    @case("E01", "NOTHING may reach the provider before the first ClientHello is judged: empty handshake records are forwarded anyway")
    def _():
        mark, pm = up().mark(), px().mark()
        s = h.tunnel(A)
        sent = b"".join(h.struct.pack(">BHH", 22, 0x0300 | (i % 256), 0) for i in range(2000))     # 2000 header-only records, version minor = payload
        s.sendall(sent)
        time.sleep(0.8)
        got_before_hello = b"".join(c.data for c in up().since(mark))
        s.sendall(rec(22, ch(b"evil.example.test")))
        d, closed = h.drain(s, 1.5)
        s.close()
        reasons = [r.get("reason") for r in px().since(pm)]
        verdict("E01", "pre-authorization bytes", len(got_before_hello) == 0,
                f"provider received {len(got_before_hello)} bytes BEFORE any ClientHello was judged; they equal what was sent: {got_before_hello == sent}; "
                f"later cut reasons={reasons}",
                "0 bytes (the gate holds everything until the first hello is judged)",
                note="finding L-2: each record header carries one attacker-chosen byte (record version minor), ~200 KB per connection up to the 1 MiB budget")

    @case("E02", "same, via a REAL OpenSSL-backed TLS server: does it tolerate the empty handshake records before a good hello?")
    def _():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CTX["ca"])
        ctx.check_hostname = False
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname=B)
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = out.read()
        s = h.tunnel(B)
        s.sendall(h.struct.pack(">BHH", 22, 0x0303, 0) * 3 + hello)
        s.settimeout(3)
        res = "no answer"
        try:
            d = s.recv(65536)
            res = "server answered with %d bytes (first byte %#x: %s)" % (len(d), d[0], {22: "handshake", 21: "ALERT"}.get(d[0], "?")) if d else "closed"
        except OSError as e:
            res = type(e).__name__
        s.close()
        verdict("E02", "real server vs empty handshake records", True, res, "INFO: how a real TLS stack reacts (qualifies E01's impact)")

    @case("E03", "INFO residual - domain fronting by Host header: SNI = CONNECT host, HTTP Host = something else, inside TLS")
    def _():
        mark = up().mark()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CTX["ca"])
        ctx.check_hostname = False
        s = h.tunnel(B)
        t = ctx.wrap_socket(s, server_hostname=B)
        t.sendall(b"GET /exfil HTTP/1.1\r\nHost: victim.unlisted.example\r\nConnection: close\r\n\r\n")
        t.recv(4096)
        conns = up().since(mark)
        host = [ln for ln in conns[0].http.split(b"\r\n") if ln.lower().startswith(b"host:")] if conns else []
        verdict("E03", "Host header differs from SNI", True, f"provider decrypted request with {host}: SNI was {conns[0].sni if conns else None}",
                "INFO: not detectable without terminating TLS; depends entirely on the provider edge rejecting SNI/Host mismatch")
    @case("B03", "slot exhaustion: 16 idle connections hold the 16 slots; the 17th gets 503 (busy) quickly; it recovers afterwards")
    def _():
        holders = [h.connect() for _ in range(16)]
        time.sleep(0.5)
        t0 = time.monotonic()
        st, rs, _ = h.request(h.connect_line(f"{A}:443"), timeout=3)
        dt = time.monotonic() - t0
        for s in holders:
            s.close()
        time.sleep(0.5)
        again = h.request(h.connect_line(f"{A}:443"))[0]
        verdict("B03", "busy proxy", st == "503" and rs == "busy" and dt < 2 and again == "200", f"17th: {st} {rs} in {dt:.2f}s; after release: {again}",
                "503 busy fast, then 200")

    @case("B04", "connection flood: 800 connections (half silent, half junk) do not crash the proxy or leak descriptors")
    def _():
        fds0 = px().fds()
        socks = []
        for i in range(800):
            try:
                s = h.connect(timeout=3)
            except OSError:
                break
            if i % 2:
                try:
                    s.sendall(b"\x00" * 3000)
                except OSError:
                    pass
            socks.append(s)
        time.sleep(1.0)
        peak = px().fds()
        for s in socks:
            s.close()
        time.sleep(1.5)
        alive = px().alive()
        ok = alive and px().fds() <= fds0 + 3
        st = h.request(h.connect_line(f"{A}:443"))[0]
        verdict("B04", "connection flood", ok and st == "200", f"alive={alive} fds {fds0} -> peak {peak} -> {px().fds()}; after: {st}",
                "alive, descriptors returned to baseline, serving")

    @case("B05", "log flooding: refusals are one JSON line each (an agent can rotate the audit trail away: measured, INFO)")
    def _():
        pm = px().mark()
        t0 = time.monotonic()
        n = 3000
        for _ in range(n):
            s = h.connect()
            s.sendall(h.connect_line("evil.test:443"))
            s.recv(200)
            s.close()
        dt = time.monotonic() - t0
        lines = len(px().since(pm))
        size = os.path.getsize(os.path.join(CTX["work"], "proxy.log"))
        verdict("B05", "audit-log volume", True, f"{n} refusals in {dt:.1f}s -> {lines} log lines, proxy.log {size // 1024} KiB total "
                f"(~{size / max(1, lines):.0f} B/line): 30 MB of json-file rotation is exhausted by ~{30_000_000 // max(1, int(size / max(1, lines)))} refusals",
                "INFO: no rate limit on audit lines; a hostile agent can age out earlier evidence", note="finding L-1")

    @case("B06", "timeouts: a hello trickled one byte per 0.5 s is cut by the hello timeout (15 s), not held forever")
    def _():
        pm = px().mark()
        s = h.tunnel(A)
        data = rec(22, good)
        t0 = time.monotonic()
        closed = False
        for b in data:
            try:
                s.sendall(bytes([b]))
            except OSError:
                closed = True
                break
            time.sleep(0.5)
            if time.monotonic() - t0 > 22:
                break
        d, c2 = h.drain(s, 1.0)
        s.close()
        dt = time.monotonic() - t0
        got = [r.get("verdict") for r in px().since(pm)]
        verdict("B06", "slow hello", (closed or c2) and 13 < dt < 20 and "timeout" in got, f"closed after {dt:.1f}s verdicts={got}", "timeout at ~15 s")

    # ================================================================================ positive controls with REAL TLS
    def real_tls(sni, connect_host, *, version=None, verify_name=None, fragment_size=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CTX["ca"])
        ctx.check_hostname = False
        if version:
            ctx.minimum_version = ctx.maximum_version = version
        s = h.tunnel(connect_host)
        s.settimeout(5)
        if fragment_size is None:
            t = ctx.wrap_socket(s, server_hostname=sni)
            t.sendall(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
            body = b""
            try:
                while True:
                    d = t.recv(4096)
                    if not d:
                        break
                    body += d
            except OSError:
                pass
            return t.version(), body
        # a real handshake whose ClientHello is re-cut into small records
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname=sni)
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        first = out.read()
        payload = b""
        pos = 0
        while pos < len(first):
            ln = int.from_bytes(first[pos + 3:pos + 5], "big")
            payload += first[pos + 5:pos + 5 + ln]
            pos += 5 + ln
        for p in h.fragment(payload, [fragment_size]):
            s.sendall(rec(22, p))
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                if out.pending:
                    s.sendall(out.read())
                d = s.recv(65536)
                if not d:
                    raise ConnectionError("closed during handshake")
                inc.write(d)
        if out.pending:
            s.sendall(out.read())
        obj.write(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
        s.sendall(out.read())
        body = b""
        s.settimeout(3)
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                inc.write(d)
                try:
                    body += obj.read(4096)
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError:
                    break
        except OSError:
            pass
        return obj.version(), body

    for cid, ver in (("P01", None), ("P02", ssl.TLSVersion.TLSv1_2), ("P03", ssl.TLSVersion.TLSv1_3)):
        @case(cid, f"real TLS ({ver.name if ver else 'negotiated'}) with certificate verification completes through the gate")
        def _(cid=cid, ver=ver):
            mark = up().mark()
            try:
                v, body = real_tls(B, B, version=ver)
                conns = up().since(mark)
                ok = body.endswith(b"ok") and conns and conns[0].sni == B
                verdict(cid, f"real TLS {ver.name if ver else 'negotiated'}", ok, f"version={v} body={body[-12:]!r} provider_saw_sni={conns[0].sni if conns else None}",
                        "handshake + HTTP response, SNI reaches the provider")
            except Exception as e:
                verdict(cid, "real TLS", False, f"{type(e).__name__}: {e}", "handshake completes")

    for n, size in enumerate([1, 5, 50], 1):
        @case(f"P1{n}", f"real TLS handshake whose ClientHello is cut into {size}-byte records completes")
        def _(n=n, size=size):
            mark = up().mark()
            try:
                v, body = real_tls(B, B, fragment_size=size)
                conns = up().since(mark)
                verdict(f"P1{n}", f"fragmented real hello ({size} B records)", body.endswith(b"ok") and conns and conns[0].sni == B,
                        f"version={v} body={body[-12:]!r}", "completes (compatibility with fragmenting clients)")
            except Exception as e:
                verdict(f"P1{n}", "fragmented real hello", False, f"{type(e).__name__}: {e}", "completes")

    @case("P20", "real TLS client naming ANOTHER site in its hello (SNI swap on a shared edge): cut before the provider sees a byte")
    def _():
        mark, pm = up().mark(), px().mark()
        try:
            real_tls("other.example.test", B)
            res = "handshake completed"
        except Exception as e:
            res = f"{type(e).__name__}"
        conns = up().since(mark)
        got = [r.get("reason") for r in px().since(pm)]
        n = sum(len(c.data) for c in conns) + sum(1 for c in conns if c.sni)
        verdict("P20", "real SNI swap", res != "handshake completed" and "tls-sni-mismatch" in got and n == 0, f"client={res} reasons={got} provider_bytes={n}",
                "cut, 0 bytes, tls-sni-mismatch")

    @case("P21", "real client: SNI = allowed name A but CONNECT to allowed name B: cut")
    def _():
        mark, pm = up().mark(), px().mark()
        try:
            real_tls(A, B)
            res = "handshake completed"
        except Exception as e:
            res = type(e).__name__
        got = [r.get("reason") for r in px().since(pm)]
        verdict("P21", "cross allow-list swap", res != "handshake completed" and "tls-sni-mismatch" in got, f"client={res} reasons={got}", "cut")

    # ================================================================================ configuration
    def start_proxy(env, timeout=3):
        e = {"PATH": os.environ["PATH"], "EGRESS_LISTEN": "127.0.0.1:3999", **env}
        p = subprocess.Popen([h.PYTHON, "-IB", h.PROXY_PY], env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out, _ = p.communicate(timeout=timeout)
            return p.returncode, out.decode(errors="replace")
        except subprocess.TimeoutExpired:
            p.terminate()
            out, _ = p.communicate(timeout=3)
            return None, out.decode(errors="replace")

    @case("C01", "an invalid or dangerous EGRESS_ALLOW makes the proxy refuse to start (fail closed), never widen")
    def _():
        bad = ["", " , ", "*.anthropic.com", "api.anthropic.com:443", "10.0.0.1", "1.2.3.4", "localhost", "single", "API.Anthropic.com,ok", "a..b.com",
               "-bad.example.com", "bad-.example.com", "xn--e1afmkfd.example.comé", "a b.example.com", "example.com.", "ex_ample.com", "a.b.123"]
        rows = []
        for v in bad:
            rc, out = start_proxy({"EGRESS_ALLOW": v})
            rows.append((v, rc))
        # lowercase normalisation is accepted for "API.Anthropic.com,ok"? ("ok" is single-label so the whole list is refused)
        ok = all(rc == 2 for v, rc in rows)
        verdict("C01", "allow-list validation", ok, str([(v, rc) for v, rc in rows if rc != 2]) or "all refused with exit 2", "exit 2 for every invalid list")

    @case("C02", "limits on EGRESS_MAX_CLIENTS / EGRESS_LISTEN")
    def _():
        rows = [(v, start_proxy({"EGRESS_ALLOW": "a.example.com", "EGRESS_MAX_CLIENTS": v})[0]) for v in ("0", "257", "-1", "x")]
        verdict("C02", "max clients bounds", all(rc in (2, 1) for _, rc in rows), str(rows), "refused")
