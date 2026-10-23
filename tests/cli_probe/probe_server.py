"""Observation endpoints for tests/cli_probe/run_probe.sh (inside a throwaway network namespace
that has nothing but loopback):

  127.0.0.1:53    a resolver that records every query and answers REFUSED (so a CLI that
                  resolves names itself is SEEN doing it, and gets nothing)
  127.0.0.1:3128  a proxy that records the request line of every request; for CONNECT it answers
                  200, reads the first ClientHello and records SNI / ECH / ALPN using the real
                  proxy's parser (docker/egress_proxy.py), then closes. Nothing is forwarded:
                  there is no network to forward to.

Usage: probe_server.py <log.jsonl>
"""
import asyncio
import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "docker"))
import egress_proxy as ep  # noqa: E402

LOG = open(sys.argv[1], "a", buffering=1)


def log(**rec):
    LOG.write(json.dumps(rec, sort_keys=True) + "\n")


def qname(packet: bytes) -> tuple[str, int]:
    p, labels = 12, []
    while p < len(packet) and packet[p]:
        n = packet[p]
        labels.append(packet[p + 1:p + 1 + n].decode("ascii", "replace"))
        p += 1 + n
    qtype = struct.unpack(">H", packet[p + 1:p + 3])[0] if p + 3 <= len(packet) else 0
    return ".".join(labels), qtype


def refused(packet: bytes) -> bytes:
    # same id, QR=1, RD copied, RA=1, RCODE=5 (REFUSED); echo the question section
    flags = 0x8000 | (packet[2] << 8 & 0x0100) | 0x0080 | 5
    return packet[:2] + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + packet[12:]


class UDPDNS(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.t = transport

    def datagram_received(self, data, addr):
        if len(data) >= 12:
            name, qtype = qname(data)
            log(kind="dns", proto="udp", name=name, qtype=qtype)
            self.t.sendto(refused(data), addr)


async def tcp_dns(reader, writer):
    try:
        n = struct.unpack(">H", await reader.readexactly(2))[0]
        data = await reader.readexactly(n)
        name, qtype = qname(data)
        log(kind="dns", proto="tcp", name=name, qtype=qtype)
        out = refused(data)
        writer.write(struct.pack(">H", len(out)) + out)
        await writer.drain()
    except Exception:
        pass
    writer.close()


async def proxy(reader, writer):
    try:
        buf = bytearray()
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = await asyncio.wait_for(reader.read(4096), 15)
            if not chunk:
                return
            buf += chunk
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        line = head.split(b"\r\n")[0].decode("ascii", "replace")
        method, _, target = line.partition(" ")
        target = target.rpartition(" ")[0]
        rec = {"kind": "request", "method": method, "target": target}
        if method != "CONNECT":
            log(**rec)
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
            return
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        stream = ep.RecordStream()
        stream.feed(rest)
        hello = None
        while hello is None:
            r = stream.next_record()
            if r is None:
                chunk = await asyncio.wait_for(reader.read(65536), 15)
                if not chunk:
                    break
                stream.feed(chunk)
                continue
            ctype, _, payload = r
            if ctype != ep.CT_HANDSHAKE:
                rec["first_record_type"] = ctype
                break
            for mtype, body in stream.handshake_messages(payload):
                if mtype == ep.HS_CLIENT_HELLO:
                    hello = ep.parse_client_hello(body)
                    break
        if hello is not None:
            rec.update(sni=hello["sni"], ech=hello["ech"], alpn=hello["alpn"])
        log(**rec)
    except Exception as e:  # recorded, never fatal: the probe observes, it does not judge
        log(kind="probe-error", error=f"{type(e).__name__}: {e}"[:200])
    finally:
        writer.close()


async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UDPDNS, local_addr=("127.0.0.1", 53))
    await asyncio.start_server(tcp_dns, "127.0.0.1", 53, family=socket.AF_INET)
    await asyncio.start_server(proxy, "127.0.0.1", 3128, family=socket.AF_INET)
    log(kind="ready")
    await asyncio.Event().wait()


asyncio.run(main())
