"""Root-only administrative recovery. NOT reachable over the broker socket: these functions
are not in OPERATIONS, ``handle_request`` rejects them, and the CLI refuses to run unless the
caller is uid 0 (sudo). They never start or stop containers on their own authority except
``reconcile``, which is the same restore the broker already performs.

Everything is audited with the operator and the stated reason; nothing is ever deleted.
"""
import json
import os
import shutil

from hunter.rsm.broker import Broker
from hunter.rsm.store import StateCorrupt


class AdminError(RuntimeError):
    pass


def require_root() -> None:
    if os.geteuid() != 0:
        raise AdminError("administrative commands must run as root (use sudo)")


def operator() -> str:
    return f"uid={os.geteuid()} sudo_user={os.environ.get('SUDO_USER', '-')}"


def _reason(text: str) -> str:
    text = (text or "").strip()
    if len(text) < 10:
        raise AdminError("--reason must explain what was done and why (>= 10 characters)")
    return text


def show(broker: Broker) -> dict:
    """Never raises on corruption: shows exactly what is on disk."""
    store = broker.store
    out: dict = {"state_file": str(store.state_path), "backup_file": str(store.backup_path)}
    try:
        out["state"] = store.load()
    except StateCorrupt as exc:
        out["state_error"] = str(exc)
        try:
            out["state_raw"] = store.state_path.read_text()[:4000]
        except OSError as e:
            out["state_raw_error"] = str(e)
    out["backup"] = store.load_backup()
    return out


def abandon(broker: Broker, reason: str, force: bool = False) -> dict:
    """Release a session that cannot be restored (e.g. a container was deleted for good).

    Records which snapshot services are still not running and why, keeps the audit trail,
    and clears the active session so the host can accept new sessions. It does not touch
    any container."""
    reason = _reason(reason)
    store = broker.store
    with store.lock() as got:
        if not got:
            raise AdminError("another broker operation is in progress; retry in a moment")
        state = store.load()                       # StateCorrupt propagates: use recover-state
        s = state["session"]
        if s is None:
            raise AdminError("no active session to abandon")
        if s["phase"] != "restore_failed" and not force:
            raise AdminError(f"session is in phase {s['phase']!r}; abandon is for "
                             "'restore_failed' (use --force only if you verified the host)")
        unresolved = []
        for entry in s["snapshot"]:
            info = broker.docker.inspect(entry["name"]) if entry["name"] in \
                broker.policy.containers else None
            if info is None or not info.running:
                unresolved.append({"container": entry["name"],
                                   "state": "missing" if info is None else "stopped",
                                   "failure": s["failures"].get(entry["name"])})
        record = {"id": s["id"], "outcome": "abandoned", "finished_at": store.clock(),
                  "stopped": s["stopped"], "failures": s["failures"], "reason": reason,
                  "unresolved": unresolved, "operator": operator()}
        state["history"] = (state.get("history") or [])[-19:] + [record]
        state["session"] = None
        store.save(state)
        store.audit("abandoned", session_id=s["id"], reason=reason, unresolved=unresolved,
                    operator=operator())
        return {"ok": True, "code": "abandoned", "session_id": s["id"], "unresolved": unresolved}


def reconcile(broker: Broker) -> dict:
    """One restore attempt now, on the administrator's authority (same code path as the
    watchdog), regardless of phase or deadline."""
    res = broker.emergency_restore()
    broker.store.audit("admin_reconcile", operator=operator(), code=res.get("code"))
    return res


def recover_state(broker: Broker, mode: str, reason: str, containers_verified: bool = False
                  ) -> dict:
    """Explicit, administrator-controlled handling of a corrupt ``session.json``.

    ``backup``  - install the last known-good snapshot (written on every save). Whatever was
                  corrupt is preserved next to it as ``session.json.corrupt-<ts>``.
    ``discard`` - start from an empty state. Only with ``containers_verified``: you assert
                  that every container that should be running IS running, because the
                  snapshot that would have told us is being given up.
    """
    reason = _reason(reason)
    store = broker.store
    with store.lock() as got:
        if not got:
            raise AdminError("another broker operation is in progress; retry in a moment")
        try:
            store.load()
        except StateCorrupt:
            pass
        else:
            raise AdminError("the state file is readable; nothing to recover")
        evidence = store.dir / f"session.json.corrupt-{int(store.clock())}"
        shutil.copy2(store.state_path, evidence)           # preserved, never renamed away
        if mode == "backup":
            backup = store.load_backup()
            if backup is None:
                raise AdminError("no valid backup exists; inspect the files and use "
                                 "`recover-state --discard` only after verifying containers")
            os.replace(store.backup_path, store.state_path)
            store.audit("state_recovered_from_backup", evidence=str(evidence),
                        reason=reason, operator=operator(),
                        session=(backup["session"] or {}).get("id"))
            return {"ok": True, "code": "recovered_from_backup", "evidence": str(evidence),
                    "active_session": (backup["session"] or {}).get("id"),
                    "must_restore": [e["name"] for e in
                                     (backup["session"] or {}).get("snapshot", [])]}
        if mode == "discard":
            if not containers_verified:
                raise AdminError("--discard requires --containers-verified (you confirm no "
                                 "container is left stopped)")
            tmp = store.state_path.with_suffix(".new")
            tmp.write_text(json.dumps({"version": 1, "session": None, "history": []}))
            os.replace(tmp, store.state_path)
            store.audit("state_discarded", evidence=str(evidence), reason=reason,
                        operator=operator())
            return {"ok": True, "code": "discarded", "evidence": str(evidence)}
        raise AdminError("mode must be 'backup' or 'discard'")
