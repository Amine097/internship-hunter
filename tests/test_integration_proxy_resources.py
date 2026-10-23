"""Resource limits of the egress proxy (docker/egress_proxy.py, PR #14), against the real Proxy.

The first QA review found that HELLO_TIMEOUT was applied to each read(), not to the whole phase: a
client that sends one byte just inside the timeout, forever, kept its slot, and MAX_CLIENTS of them
locked the agent out of its own provider (a self-DoS of that agent's egress, not a route out).
#14 replaced it with ABSOLUTE deadlines counted from the `200` (`Tunnel._read_before`). These tests
keep it fixed, with the two controls that make a pass mean something:

  * CONTROL      while the drippers are inside their deadline all four slots really are held (a
                 fifth CONNECT is answered 503 "busy"), so the later 200 is not a proxy that never
                 counted slots;
  * NEGATIVE     the old per-read behaviour, patched into the real Tunnel class, keeps the slots for
                 the whole test: the same measurement fails on it.

Scaled down: HELLO_TIMEOUT = 1 s, a byte every 0.7 s. PROXY_DIR points at a directory holding
egress_proxy.py (default: docker/); skipped when absent.
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


@pytest.fixture
def ep(monkeypatch):
    monkeypatch.syspath_prepend(str(PROXY_DIR))
    sys.modules.pop("egress_proxy", None)
    import egress_proxy

    monkeypatch.setattr(egress_proxy, "HELLO_TIMEOUT", 1.0)
    return egress_proxy


def _per_read_timeout(ep):
    """The behaviour the first review found: while the ClientHello is incomplete, every read gets
    the full HELLO_TIMEOUT again. Everything else (the server side, the handshake budget) is the
    real code, so the only difference from the shipped proxy is the one defect."""
    real = ep.Tunnel._read_before

    async def _read_before(self, reader, deadline, reason):
        if reason != "hello-deadline":
            return await real(self, reader, deadline, reason)
        try:
            return await self._read(reader, ep.HELLO_TIMEOUT)
        except TimeoutError:
            raise ep.Deadline(reason) from None

    return _read_before


def _drip(ep):
    """Four drippers (a byte every 0.7 s, never completing) against a proxy with four slots.
    Returns the status a fifth CONNECT gets (a) during the drip, inside the deadline, and (b) after
    five hello deadlines."""

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

        async def probe():
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(req)
            line = (await asyncio.wait_for(r.read(300), 5)).split(b"\r\n")[0]
            w.close()
            return line

        tasks = [asyncio.create_task(dripper()) for _ in range(4)]
        await asyncio.sleep(0.4)  # all four are past the 200 and inside their 1 s deadline
        during = await probe()
        await asyncio.sleep(4.6)  # five hello deadlines in all
        after = await probe()
        for t in tasks:
            t.cancel()
        srv.close()
        usrv.close()
        return during, after

    return asyncio.run(scenario())


def test_control_while_the_drippers_are_inside_their_deadline_every_slot_is_held(ep):
    during, _after = _drip(ep)
    assert b" 503 " in during, f"a fifth CONNECT inside the deadline got: {during!r}"


def test_a_trickled_client_hello_does_not_hold_a_slot_past_the_hello_deadline(ep):
    _during, after = _drip(ep)
    assert b" 200 " in after, f"a legitimate CONNECT after five deadlines got: {after!r}"


def test_negative_control_a_per_read_timeout_would_keep_the_slots(ep, monkeypatch):
    """Re-introduce the original defect into the real class: the same measurement must fail."""
    monkeypatch.setattr(ep.Tunnel, "_read_before", _per_read_timeout(ep))
    during, after = _drip(ep)
    assert b" 503 " in during
    assert b" 503 " in after, f"the old behaviour was not detected: a CONNECT got {after!r}"
