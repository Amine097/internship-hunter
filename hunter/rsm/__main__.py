"""Entry point: python -m hunter.rsm {serve|watchdog|recover|status|plan|admin ...}"""
import argparse
import json
import logging
import sys

from hunter.rsm import admin, notify
from hunter.rsm.broker import Broker
from hunter.rsm.dockerctl import CliDocker
from hunter.rsm.policy import PolicyError, load_policy
from hunter.rsm.server import RsmServer
from hunter.rsm.store import Store

log = logging.getLogger("hunter.rsm")
ALERT_MIN_INTERVAL = 1800   # at most one host alert per 30 min per problem


def build(args) -> Broker:
    policy = load_policy(args.policy, check_permissions=not args.insecure_policy_permissions)
    return Broker(policy, CliDocker(args.docker_bin), Store(args.state_dir))


def common() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--policy", default="/etc/hunter-rsm/policy.json")
    ap.add_argument("--state-dir", default="/var/lib/hunter-rsm")
    ap.add_argument("--docker-bin", default="/usr/bin/docker")
    ap.add_argument("--insecure-policy-permissions", action="store_true",
                    help="tests only: skip the root-owned/not-writable policy check")
    ap.add_argument("--insecure-no-root-check", action="store_true",
                    help="tests only: skip the uid-0 requirement of `admin`")
    return ap


def main(argv=None) -> int:
    parent = common()
    ap = argparse.ArgumentParser(prog="hunter.rsm")
    sub = ap.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", parents=[parent])
    serve.add_argument("--systemd", action="store_true",
                       help="inherit the listening socket from systemd (LISTEN_FDS)")
    serve.add_argument("--socket", default=None, help="standalone/dev mode only")
    serve.add_argument("--allowed-uid", type=int, action="append", default=[])
    for name in ("watchdog", "recover", "status", "plan"):
        sub.add_parser(name, parents=[parent])
    adm = sub.add_parser("admin", help="root-only recovery commands (never on the socket)")
    asub = adm.add_subparsers(dest="admin_command", required=True)
    for name in ("show", "reconcile"):
        asub.add_parser(name, parents=[parent])
    ab = asub.add_parser("abandon", parents=[parent])
    ab.add_argument("--reason", required=True)
    ab.add_argument("--force", action="store_true")
    rs = asub.add_parser("recover-state", parents=[parent])
    rs.add_argument("--mode", choices=["backup", "discard"], required=True)
    rs.add_argument("--reason", required=True)
    rs.add_argument("--containers-verified", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        broker = build(args)
    except PolicyError as exc:
        # An invalid policy must be LOUD: serve/watchdog exit non-zero and never act.
        print(json.dumps({"ok": False, "code": "invalid_policy", "error": str(exc)}),
              file=sys.stderr)
        return 4

    if args.command == "serve":
        if args.systemd:
            srv = RsmServer.from_systemd(broker, args.allowed_uid)
        elif args.socket:
            srv = RsmServer(args.socket, broker, args.allowed_uid)
        else:
            print("serve needs --systemd or --socket", file=sys.stderr)
            return 2
        log.info("serving (%d stoppable containers)", len(broker.policy.containers))
        try:
            srv.serve_forever()
        finally:
            srv.server_close()
        return 0

    if args.command in ("watchdog", "recover"):
        res = broker.watchdog_tick(at_boot=args.command == "recover")
        print(json.dumps(res))
        code = res.get("code")
        if code == "state_corrupt":
            if broker.store.alert_due("state_corrupt", ALERT_MIN_INTERVAL):
                notify.send(broker.policy.notify,
                            "RSM RECOVERY STATE IS CORRUPT - containers may still be stopped. "
                            "Run `sudo python3 -m hunter.rsm admin show` on the host.")
            return 3
        if code == "restored" and res.get("reason"):
            notify.send(broker.policy.notify,
                        f"RSM watchdog restored containers ({res['reason']}).")
        if code == "restore_failed":
            if broker.store.alert_due(f"restore_failed:{res.get('session_id')}",
                                      ALERT_MIN_INTERVAL):
                notify.send(broker.policy.notify,
                            "RSM RESTORE FAILED - containers still stopped: "
                            + ", ".join(sorted(res.get("failures", {}))))
            return 2
        return 0

    if args.command == "status":
        res = broker.status()
        print(json.dumps(res, indent=2))
        return 3 if res.get("code") == "state_corrupt" else 0

    if args.command == "plan":   # dry run: mutates nothing
        running = {n: broker.docker.inspect(n) for n in broker.policy.containers}
        print(json.dumps({n: (i.running if i else None) for n, i in running.items()}, indent=2))
        return 0

    # admin ---------------------------------------------------------------------------------
    try:
        if not args.insecure_no_root_check:
            admin.require_root()
        if args.admin_command == "show":
            print(json.dumps(admin.show(broker), indent=2, default=str))
        elif args.admin_command == "reconcile":
            print(json.dumps(admin.reconcile(broker), indent=2))
        elif args.admin_command == "abandon":
            print(json.dumps(admin.abandon(broker, args.reason, args.force), indent=2))
        else:
            print(json.dumps(admin.recover_state(
                broker, args.mode, args.reason, args.containers_verified), indent=2))
        return 0
    except admin.AdminError as exc:
        print(json.dumps({"ok": False, "code": "admin_refused", "error": str(exc)}),
              file=sys.stderr)
        return 5
    except RuntimeError as exc:        # StateCorrupt during abandon etc.
        print(json.dumps({"ok": False, "code": "state_corrupt", "error": str(exc)}),
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
