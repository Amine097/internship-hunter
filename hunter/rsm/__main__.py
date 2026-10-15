"""Entry point: python -m hunter.rsm {serve|watchdog|recover|status|plan} --policy P ..."""
import argparse
import json
import logging
import sys

from hunter.rsm import notify
from hunter.rsm.broker import Broker
from hunter.rsm.dockerctl import CliDocker
from hunter.rsm.policy import load_policy
from hunter.rsm.server import RsmServer
from hunter.rsm.store import Store

log = logging.getLogger("hunter.rsm")


def build(args) -> Broker:
    policy = load_policy(args.policy, check_permissions=not args.insecure_policy_permissions)
    return Broker(policy, CliDocker(args.docker_bin), Store(args.state_dir))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hunter.rsm")
    ap.add_argument("command", choices=["serve", "watchdog", "recover", "status", "plan"])
    ap.add_argument("--policy", default="/etc/hunter-rsm/policy.json")
    ap.add_argument("--state-dir", default="/var/lib/hunter-rsm")
    ap.add_argument("--socket", default="/run/hunter-rsm/rsm.sock")
    ap.add_argument("--socket-group", default=None)
    ap.add_argument("--allowed-uid", type=int, action="append", default=[])
    ap.add_argument("--docker-bin", default="/usr/bin/docker")
    ap.add_argument("--insecure-policy-permissions", action="store_true",
                    help="tests only: skip the root-owned/not-writable policy check")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    broker = build(args)

    if args.command == "serve":
        srv = RsmServer(args.socket, broker, args.socket_group, args.allowed_uid)
        log.info("serving on %s (policy: %d stoppable containers)", args.socket,
                 len(broker.policy.containers))
        try:
            srv.serve_forever()
        finally:
            srv.server_close()
        return 0
    if args.command in ("watchdog", "recover"):
        res = broker.watchdog_tick(at_boot=args.command == "recover")
        print(json.dumps(res))
        if res.get("code") in ("restored",) and res.get("reason"):
            notify.send(broker.policy.notify,
                        f"RSM watchdog restored containers ({res['reason']}).")
        if res.get("code") == "restore_failed":
            notify.send(broker.policy.notify,
                        "RSM RESTORE FAILED - containers still stopped: "
                        + ", ".join(sorted(res.get("failures", {}))))
            return 2
        return 0
    if args.command == "status":
        print(json.dumps(broker.status(), indent=2))
        return 0
    # plan: dry run, mutates nothing
    running = {n: broker.docker.inspect(n) for n in broker.policy.containers}
    print(json.dumps({n: (i.running if i else None) for n, i in running.items()}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
