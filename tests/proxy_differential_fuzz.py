"""Differential fuzz: the egress proxy's ClientHello gate vs OpenSSL as the provider (a helper
process for tests/test_integration_proxy_differential_fuzz.py).

For every mutated ClientHello stream sent through the REAL `Proxy`, whatever it forwards upstream is
fed to an OpenSSL server (ssl.SSLObject + sni_callback). A violation is
  V1  OpenSSL extracted a server name different from the CONNECT host (domain-fronting bypass)
  V2  OpenSSL progressed the handshake (produced a ServerHello) but saw no server name at all
MUTANT=prefix|anysni|noech replaces the gate with a deliberately broken one: the harness must flag
it (the positive control that makes "0 violations" mean something).

usage: proxy_differential_fuzz.py <dir holding egress_proxy.py> <iterations> <seed>
last stdout line: RESULT {json}
"""

import asyncio
import os
import random
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[1])
import egress_proxy as ep

N = int(sys.argv[2])
SEED = int(sys.argv[3])
MUTANT = os.environ.get("MUTANT", "")
if (
    MUTANT
):  # deliberately broken proxies: the oracle must flag every one of them (positive controls)
    if MUTANT == "prefix":  # startswith instead of ==

        def _chk(self, body):
            h = ep.parse_client_hello(body)
            if h["ech"] or h["sni"] is None or not h["sni"].lower().startswith(self.host):
                raise ep.TLSViolation("mutant")
            self.client_hellos += 1
            self.sni, self.alpn = h["sni"].lower(), h["alpn"]

        ep.Tunnel._check_client_hello = _chk
    elif MUTANT == "anysni":  # any SNI is fine as long as one exists

        def _chk(self, body):
            h = ep.parse_client_hello(body)
            if h["sni"] is None:
                raise ep.TLSViolation("mutant")
            self.client_hellos += 1
            self.sni, self.alpn = h["sni"].lower(), h["alpn"]

        ep.Tunnel._check_client_hello = _chk
    elif (
        MUTANT == "noech"
    ):  # no SNI requirement and no ECH check: only compares when SNI is present

        def _chk(self, body):
            h = ep.parse_client_hello(body)
            if h["sni"] is not None and h["sni"].lower() != self.host:
                raise ep.TLSViolation("mutant")
            self.client_hellos += 1
            self.sni, self.alpn = h["sni"], h["alpn"]

        ep.Tunnel._check_client_hello = _chk
    elif MUTANT == "nohold":  # the pre-fix behaviour: release every record immediately
        pass
HOST = "api.anthropic.com"
rnd = random.Random(SEED)

tmp = tempfile.mkdtemp(prefix="qa4-fuzz-")
subprocess.run(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        f"{tmp}/k.pem",
        "-out",
        f"{tmp}/c.pem",
        "-subj",
        f"/CN={HOST}",
        "-days",
        "2",
    ],
    check=True,
    capture_output=True,
)


def u16(n):
    return max(0, min(n, 0xFFFF)).to_bytes(2, "big")


def u24(n):
    return max(0, min(n, 0xFFFFFF)).to_bytes(3, "big")


def base_hello():
    """A real OpenSSL ClientHello for HOST (TLS 1.3 capable, many extensions)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=HOST)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def split_hello(rec):
    """record bytes -> (record_version, body) of the single handshake ClientHello inside."""
    assert rec[0] == 22
    hs = rec[5:]
    assert hs[0] == 1
    return rec[1:3], hs[4 : 4 + int.from_bytes(hs[1:4], "big")]


def parse_exts(body):
    p = 2 + 32
    sid = body[p]
    p += 1 + sid
    cs = int.from_bytes(body[p : p + 2], "big")
    p += 2 + cs
    cm = body[p]
    p += 1 + cm
    head = body[:p]
    el = int.from_bytes(body[p : p + 2], "big")
    p += 2
    exts = []
    end = p + el
    while p < end:
        t = int.from_bytes(body[p : p + 2], "big")
        n = int.from_bytes(body[p + 2 : p + 4], "big")
        exts.append((t, body[p + 4 : p + 4 + n]))
        p += 4 + n
    return head, exts


def build(head, exts, ver=b"\x03\x01", hs_len_delta=0, ext_len_delta=0, rec_len_delta=0):
    eb = b"".join(u16(t) + u16(len(d)) + d for t, d in exts)
    body = head + u16(len(eb) + ext_len_delta) + eb
    hs = b"\x01" + u24(len(body) + hs_len_delta) + body
    return b"\x16" + ver + u16(len(hs) + rec_len_delta) + hs


def sni_ext(names):  # names: list of (type, bytes)
    lst = b"".join(bytes([t]) + u16(len(n)) + n for t, n in names)
    return (0, u16(len(lst)) + lst)


BASE = base_hello()
VER, BODY = split_hello(BASE)
HEAD, EXTS = parse_exts(BODY)
assert any(t == 0 for t, _ in EXTS)
OTHER = [e for e in EXTS if e[0] != 0]
EVIL = b"evil.example"

NAMES = [
    HOST.encode(),
    HOST.upper().encode(),
    (HOST + ".").encode(),
    (HOST + "\x00").encode(),
    (HOST + "\x00." + "evil.example").encode(),
    b" " + HOST.encode(),
    HOST.encode() + b" ",
    ("api.anthropic.com@evil.example").encode(),
    (HOST + "%00").encode(),
    EVIL,
    ("api.anthropic.com.evil.example").encode(),
    ("evil.example." + HOST).encode(),
    b"",
    HOST.replace("a", "а").encode("utf-8"),
    HOST.encode("utf-16-le"),
    b"[::1]",
    b"127.0.0.1",
]


def mutate():
    kind = rnd.randrange(14)
    exts = list(EXTS)
    si = next(i for i, (t, _) in enumerate(exts) if t == 0)
    pre = b""
    post = b""
    kw = {}
    if kind == 0:  # odd name spellings in the one SNI
        exts[si] = sni_ext([(0, rnd.choice(NAMES))])
    elif kind == 1:  # two names, either order, either type
        a, b = rnd.choice(NAMES), rnd.choice(NAMES)
        exts[si] = sni_ext([(rnd.choice([0, 0, 1, 2, 255]), a), (rnd.choice([0, 1, 255]), b)])
    elif kind == 2:  # duplicate server_name extension
        exts.insert(rnd.randrange(len(exts) + 1), sni_ext([(0, rnd.choice(NAMES))]))
    elif kind == 3:  # no SNI / empty list
        exts.pop(si)
        if rnd.random() < 0.5:
            exts.insert(rnd.randrange(len(exts) + 1), (0, u16(0)))
    elif kind == 4:  # ECH / ESNI sprinkled in
        exts.insert(
            rnd.randrange(len(exts) + 1),
            (rnd.choice([0xFE0D, 0xFFCE, 0xFE0A]), os.urandom(rnd.randrange(0, 60))),
        )
    elif kind == 5:  # length skews
        kw = dict(
            hs_len_delta=rnd.choice([-3, -1, 0, 1, 2, 5]),
            ext_len_delta=rnd.choice([-4, -1, 0, 1, 3]),
            rec_len_delta=rnd.choice([-2, 0, 0, 1, 7]),
        )
    elif kind == 6:  # SNI name length skew inside the extension
        n = rnd.choice(NAMES)
        lst = b"\x00" + u16(len(n) + rnd.choice([-2, -1, 1, 2, 9])) + n
        exts[si] = (0, u16(len(lst) + rnd.choice([-1, 0, 0, 1])) + lst)
    elif kind == 7:  # shuffle extensions / drop random ones
        rnd.shuffle(exts)
        if rnd.random() < 0.5 and len(exts) > 2:
            exts.pop(rnd.randrange(len(exts)))
    elif kind == 8:  # junk in an unknown extension that *contains* an SNI-looking blob
        blob = sni_ext([(0, EVIL)])
        exts.insert(
            rnd.randrange(len(exts) + 1),
            (
                rnd.choice([0x1A1A, 21, 0xFF01, 41]),
                u16(blob[1].__len__()) + blob[1] + os.urandom(3),
            ),
        )
    elif kind == 9:  # two ClientHellos back to back (second one evil), same or different records
        pre = b""
        post = build(HEAD, [sni_ext([(0, EVIL)])] + OTHER)
    elif kind == 10:  # stuff before the hello (CCS / alert / appdata / empty handshake record)
        pre = rnd.choice(
            [
                b"\x14\x03\x03\x00\x01\x01",
                b"\x15\x03\x03\x00\x02\x01\x00",
                b"\x17\x03\x03\x00\x03abc",
                b"\x16\x03\x01\x00\x00",
                b"\x80\x2e\x01\x03\x01",
                b"\x16\x03\x01\x00\x01\x01",
            ]
        )
    elif kind == 11:  # random SNI chars
        exts[si] = sni_ext(
            [
                (
                    0,
                    HOST.encode()[: rnd.randrange(0, len(HOST))]
                    + bytes(rnd.choices(range(256), k=rnd.randrange(0, 5))),
                )
            ]
        )
    elif (
        kind == 12
    ):  # ClientHello with the right SNI then trailing junk handshake message in same record
        pass
    # kind 13: byte flips only
    hello = build(HEAD, exts, VER, **kw)
    if kind == 12:
        hs = hello[5:]
        hs += (
            bytes([rnd.choice([1, 2, 11, 20, 4])])
            + u24(rnd.randrange(0, 20))
            + os.urandom(rnd.randrange(0, 20))
        )
        hello = hello[:3] + u16(len(hs)) + hs
    stream = pre + hello + post
    # record-level split / flips
    if rnd.random() < 0.45:
        cuts = sorted(
            rnd.sample(range(1, max(2, len(hello) - 5)), k=min(len(hello) - 6, rnd.randrange(1, 4)))
        )
        payload = hello[5:]
        offs = [0] + [c for c in cuts if 0 < c < len(payload)] + [len(payload)]
        stream = pre
        for a, b in zip(offs, offs[1:]):
            stream += hello[:3] + u16(b - a) + payload[a:b]
        stream += post
    if kind == 13 or rnd.random() < 0.25:
        s = bytearray(stream)
        for _ in range(rnd.randrange(1, 5)):
            s[rnd.randrange(len(s))] ^= 1 << rnd.randrange(8)
        stream = bytes(s)
    return kind, stream


def openssl_judges(forwarded: bytes):
    """Feed forwarded bytes to a real OpenSSL server: (server names seen, handshake progressed)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{tmp}/c.pem", f"{tmp}/k.pem")
    seen = []

    def cb(obj, name, c):
        seen.append(name)

    ctx.sni_callback = cb
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_side=True)
    inc.write(forwarded)
    try:
        obj.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLError, OSError):
        pass
    produced = out.read()
    return seen, produced[:1] == b"\x16" and len(produced) > 5


async def one(port, stream):
    """returns bytes the proxy forwarded upstream (collector at upstream_port)."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode())
    await w.drain()
    try:
        await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 3)
    except Exception:
        w.close()
        return
    # send in 1-3 writes (segmentation must not matter to the record logic; timing may)
    i = 0
    try:
        while i < len(stream):
            j = min(len(stream), i + rnd.choice([len(stream), 7, 64, 513]))
            w.write(stream[i:j])
            await w.drain()
            i = j
            if rnd.random() < 0.1:
                await asyncio.sleep(0.002)
        w.write_eof()
    except (ConnectionError, OSError):
        pass  # the proxy cut the connection: a normal outcome
    try:
        await asyncio.wait_for(r.read(), 4)
    except Exception:
        pass
    w.close()


async def main():
    cur = {"buf": None}

    async def upstream(r, w):
        buf = bytearray()
        try:
            while True:
                d = await asyncio.wait_for(r.read(65536), 3)
                if not d:
                    break
                buf.extend(d)
        except Exception:
            pass
        if cur["buf"] is not None:
            cur["buf"].extend(buf)
        try:
            w.close()
        except Exception:
            pass

    usrv = await asyncio.start_server(upstream, "127.0.0.1", 0)
    uport = usrv.sockets[0].getsockname()[1]

    async def resolver(h):
        return ["127.0.0.1"]

    logs = []
    proxy = ep.Proxy(
        frozenset({HOST}), max_clients=64, resolver=resolver, log=logs.append, upstream_port=uport
    )
    srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    viol, slow, stats = [], [], {"forwarded": 0, "cut": 0, "ossl_progress": 0}
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(
        lambda _loop, ctx: logs.append(
            {"loop-exception": str(ctx.get("exception") or ctx.get("message"))[:200]}
        )
    )
    kinds = {}
    for it in range(N):
        kind, stream = mutate()
        cur["buf"] = bytearray()
        t0 = time.monotonic()
        await one(port, stream)
        await asyncio.sleep(0.01)
        dt = time.monotonic() - t0
        fw = bytes(cur["buf"])
        cur["buf"] = None
        if dt > 5:
            slow.append((kind, dt, stream.hex()))
        if fw:
            stats["forwarded"] += 1
            seen, prog = openssl_judges(fw)
            stats["ossl_progress"] += prog
            bad = [s for s in seen if s is None or s.lower() != HOST]
            if bad or (prog and not seen):
                viol.append(
                    {
                        "kind": kind,
                        "seen": seen,
                        "progress": prog,
                        "stream": stream.hex(),
                        "forwarded": len(fw),
                    }
                )
        else:
            stats["cut"] += 1
        kinds[kind] = kinds.get(kind, 0) + 1
    srv.close()
    usrv.close()
    exc = [r for r in logs if isinstance(r, dict) and ("loop-exception" in r)]
    print("iterations", N, "seed", SEED, stats, "kinds", dict(sorted(kinds.items())))
    print("proxy unhandled loop exceptions:", len(exc), exc[:3])
    print("slow cases (>5s):", len(slow))
    print("VIOLATIONS:", len(viol))
    for v in viol[:5]:
        print(" ", v["kind"], v["seen"], v["progress"], v["forwarded"], v["stream"][:160])
    verdicts = {}
    for r in logs:
        if isinstance(r, dict) and "verdict" in r:
            k = (r["verdict"], r.get("reason"))
            verdicts[k] = verdicts.get(k, 0) + 1
    print("proxy verdicts:", dict(sorted(verdicts.items(), key=lambda kv: -kv[1])[:14]))
    import json as _j

    print(
        "RESULT "
        + _j.dumps(
            {
                "violations": len(viol),
                "exceptions": len(exc),
                "slow": len(slow),
                "forwarded": stats["forwarded"],
                "progressed": stats["ossl_progress"],
            }
        )
    )


asyncio.run(main())
