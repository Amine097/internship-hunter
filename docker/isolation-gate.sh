#!/bin/sh
# ENTRYPOINT wrapper of every app-image service that has a route out (api, discovery, telegram):
# refuse to start the service while any EGRESS_FORBIDDEN_TARGETS (comma-separated ip:port, the
# Docker host's own addresses) is reachable from this container. After a Docker daemon restart the
# restart policy can start containers BEFORE the host guard is re-applied; this makes such a
# container exit (and be retried by the restart policy) instead of running application code
# unguarded. It probes with a bare connect() - connected or ECONNREFUSED both mean "the host
# answered" - and sends no data. It only knows the targets it was given; the host guard is the
# complete policy (docs/deployment.md, "Startup window"). Empty list: no check (development, CI).
set -eu
if [ -n "${EGRESS_FORBIDDEN_TARGETS:-}" ]; then
  py="$(command -v python || command -v python3 || true)"
  [ -n "$py" ] || { echo "isolation-gate: python not found: refusing to start" >&2; exit 1; }
  "$py" - <<'PY' || { echo "isolation-gate: refusing to start: host isolation is not in place" >&2; exit 1; }
import errno, os, re, socket, sys
OK = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPERM, errno.EACCES, errno.ETIMEDOUT,
      errno.ENETDOWN}
bad = []
for t in os.environ["EGRESS_FORBIDDEN_TARGETS"].replace(" ", "").split(","):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d{1,5}", t):
        bad.append(f"malformed target {t!r}")
        continue
    host, port = t.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        bad.append(f"{t} is reachable (connected)")
    except (ConnectionRefusedError, ConnectionResetError):
        bad.append(f"{t} answered (connection refused)")
    except TimeoutError:
        pass
    except OSError as e:
        if e.errno not in OK:
            bad.append(f"{t}: unclassifiable error {e}")
for b in bad:
    print(f"isolation-gate: {b}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
fi
exec "$@"
