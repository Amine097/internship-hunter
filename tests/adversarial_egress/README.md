# Independent adversarial tests for PR #14 (`docker/egress_proxy.py`)

Reviewer-owned; not part of the PR's branch. Everything is self-contained and unprivileged.

* `harness.py` + `cases.py`: ~180 black-box expectations against the REAL, UNMODIFIED proxy process.
  Everything runs in one private `unshare -Urnm` namespace: a genuinely global address on `lo`, `/etc/hosts` and
  `/etc/resolv.conf` bind-mounted over with ours (so the proxy's own `getaddrinfo` path and production port 443 are
  exercised), a recording "provider" (what it RECEIVED is the ground truth), a real OpenSSL TLS server with a private CA
  for the positive controls, and hand-built HTTP heads / TLS records / ClientHellos.

      EGRESS_PYTHON=<python 3.12> python3 tests/adversarial_egress/harness.py [--only PREFIX] [--json out.json]
      EGRESS_PROXY_PY=<other copy of egress_proxy.py> ...   # e.g. a patched copy

* `test_topology_lab.py`: the repository's real compose topology on a throwaway rootless Docker (the repo's own
  `tests/rootless_lab/lab.sh`), a listener on every probed port: every ordered pair of containers must connect exactly
  when they share a network. `REV14_MUTATE=1` wires an agent to another proxy's network to prove the detector bites.
  Opt-in: `HUNTER_ROOTLESS_LAB=1`; set `GUARD_IPTABLES_DIR` if `iptables` is not on PATH.

* `proposed_fix.patch`: the three code changes that close findings 1 and 2 (apply with `git apply`).
