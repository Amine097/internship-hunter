"""Run docker/egress_proxy.py unchanged (its own Proxy class, parser and TLS gate) inside the
sandbox. The ONLY substitution is the resolver: the allow-listed name maps to 127.0.0.1, where the
fake upstream listens (the real resolve() would, correctly, refuse a loopback address; that part is
exercised separately by rebind14.py)."""

import asyncio
import importlib.util
import os
import sys

# argv[1]: the proxy module (default: the repo's docker/egress_proxy.py)
path = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docker", "egress_proxy.py"
    )
)
spec = importlib.util.spec_from_file_location("egress_proxy", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
allow = m.parse_allowlist(os.environ["EGRESS_ALLOW"])


async def resolver(host):
    return ["127.0.0.1"]


async def main():
    proxy = m.Proxy(allow, 16, resolver=resolver, log=lambda rec: None)
    srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 3128)
    async with srv:
        await srv.serve_forever()


asyncio.run(main())
