"""Does the egress proxy's ClientHello gate agree with a real TLS server about the server name?

The proxy (docker/egress_proxy.py, PR #14) forwards a ClientHello only if its own parser finds
exactly one server_name equal to the CONNECT host. If that parser and the provider's disagree
(duplicate extensions, odd lengths, a name list, a split or coalesced record, junk around it), a
hostile agent names an allowed host in CONNECT and another one in the hello: domain fronting through
the gate. tests/proxy_differential_fuzz.py mutates ClientHellos structurally, sends each through the
real `Proxy`, and gives whatever is forwarded to OpenSSL's server code, whose sni_callback is the
oracle. The mutants (a prefix match, any SNI, no SNI requirement) are the positive controls: the
oracle must see them, otherwise "0 violations" is only silence.

PROXY_DIR points at a directory holding egress_proxy.py (default: docker/ of this checkout); the
tests skip when it is absent (the proxy lives in PR #14). FUZZ_ITERATIONS (default 300) scales it.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PROXY_DIR = Path(os.environ.get("PROXY_DIR") or HERE.parent / "docker")
FUZZ = HERE / "proxy_differential_fuzz.py"
N = os.environ.get("FUZZ_ITERATIONS", "300")

pytestmark = [
    pytest.mark.skipif(not (PROXY_DIR / "egress_proxy.py").exists(), reason="no egress_proxy.py"),
    pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI"),
]


def _run(seed, mutant=""):
    r = subprocess.run(
        [sys.executable, "-I", str(FUZZ), str(PROXY_DIR), N, str(seed)],
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, "MUTANT": mutant},
    )
    last = [ln for ln in r.stdout.splitlines() if ln.startswith("RESULT ")]
    assert last, r.stdout[-1500:] + r.stderr[-1500:]
    return json.loads(last[-1][len("RESULT ") :])


@pytest.mark.parametrize("seed", [1, 2])
def test_the_gate_and_openssl_agree_on_every_forwarded_hello(seed):
    res = _run(seed)
    assert res["violations"] == 0, res
    assert res["exceptions"] == 0 and res["slow"] == 0, res
    # the run must have exercised the forwarding path, or agreement proves nothing
    assert res["forwarded"] > 20 and res["progressed"] > 10, res


@pytest.mark.parametrize("mutant", ["prefix", "anysni", "noech"])
def test_the_oracle_sees_a_broken_gate(mutant):
    assert _run(1, mutant)["violations"] > 0
