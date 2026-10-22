"""Resource limits of the egress proxy (docker/egress_proxy.py, PR #14), against the real Proxy.

HELLO_TIMEOUT is documented as "seconds after `200` until the first ClientHello is complete", but it
is applied to each read(), not to the whole phase: a client that sends one byte just inside the
timeout, forever, keeps its slot. The proxy serves ONE agent, so the victim is that agent's own
egress (it can lock itself out of its provider with MAX_CLIENTS dripping connections); it is not a
route out. Scaled down here: HELLO_TIMEOUT = 1 s, a byte every 0.7 s.

PROXY_DIR points at a directory holding egress_proxy.py (default: docker/); skipped when absent.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

PROXY_DIR = Path(os.environ.get("PROXY_DIR") or Path(__file__).resolve().parents[1] / "docker")
pytestmark = pytest.mark.skipif(
    not (PROXY_DIR / "egress_proxy.py").exists(), reason="no egress_proxy.py"
)
HOST = "api.anthropic.com"


def _hello():
    name = HOST.encode()
    sn = b"\x00" + len(name).to_bytes(2, "big") + name
    sn = len(sn).to_bytes(2, "big") + sn
    ext = b"\x00\x00" + len(sn).to_bytes(2, "big") + sn
    body = (
        b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        + len(ext).to_bytes(2, "big") + ext
    )  # fmt: skip
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


@pytest.mark.xfail(
    strict=True,
    reason="HELLO_TIMEOUT is per read(): a ClientHello trickled one byte per interval holds a slot "
    "indefinitely (bounded only by the 1 MiB inspection budget)",
)
def test_a_trickled_client_hello_does_not_hold_a_slot_past_the_hello_deadline(monkeypatch):
    monkeypatch.syspath_prepend(str(PROXY_DIR))
    sys.modules.pop("egress_proxy", None)
    import egress_proxy as ep

    monkeypatch.setattr(ep, "HELLO_TIMEOUT", 1.0)

    async def scenario():
        async def sink(r, w):
            await r.read()

        usrv = await asyncio.start_server(sink, "127.0.0.1", 0)

        async def resolver(_host):
            return ["127.0.0.1"]

        proxy = ep.Proxy(
            frozenset({HOST}), max_clients=4, resolver=resolver, log=lambda _r: None,
            upstream_port=usrv.sockets[0].getsockname()[1],
        )  # fmt: skip
        srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        req = f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode()

        async def dripper():
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(req)
            await r.readuntil(b"\r\n\r\n")
            try:
                for b in _hello()[:-1]:  # never completes
                    w.write(bytes([b]))
                    await w.drain()
                    await asyncio.sleep(0.7)
            except (ConnectionError, OSError):
                pass

        tasks = [asyncio.create_task(dripper()) for _ in range(4)]
        await asyncio.sleep(5.0)  # five hello deadlines
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(req)
        status = (await asyncio.wait_for(r.read(300), 5)).split(b"\r\n")[0]
        for t in tasks:
            t.cancel()
        srv.close()
        usrv.close()
        return status

    status = asyncio.run(scenario())
    assert b" 200 " in status, f"a legitimate CONNECT after five deadlines got: {status!r}"
