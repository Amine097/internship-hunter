"""The five operations. Everything here is idempotent and crash-safe: state is persisted
before and after every Docker action, and `restore` is derived from the durable snapshot,
not from in-memory progress."""
import time
from collections.abc import Callable

from hunter.rsm import probes as probes_mod
from hunter.rsm.dockerctl import DockerController, DockerError
from hunter.rsm.policy import SESSION_ID, Policy, stop_order
from hunter.rsm.store import Store

ACTIVE_PHASES = ("prepared", "stopping", "stopped", "restoring", "restore_failed")


def read_mem_available_mib(path: str = "/proc/meminfo") -> int:
    with open(path) as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    raise RuntimeError("MemAvailable not found")


class Broker:
    def __init__(self, policy: Policy, docker: DockerController, store: Store,
                 clock: Callable[[], float] = time.time,
                 mem_available: Callable[[], int] = read_mem_available_mib,
                 probe_runner: Callable = probes_mod.run_probe):
        self.policy, self.docker, self.store = policy, docker, store
        self.clock, self.mem, self.run_probe = clock, mem_available, probe_runner

    # ------------------------------------------------------------------ helpers -------------
    def _result(self, ok: bool, code: str, **extra) -> dict:
        return {"ok": ok, "code": code, **extra}

    def _public(self, s: dict | None) -> dict | None:
        if not s:
            return None
        now = self.clock()
        return {
            "session_id": s["id"], "phase": s["phase"],
            "seconds_remaining": max(0, int(s["deadline"] - now)),
            "to_stop": s["stop_order"], "stopped": s["stopped"], "skipped_busy": s["skipped"],
            "failures": s["failures"], "mem_available_before_mib": s.get("mem_before"),
            "mem_available_after_mib": s.get("mem_after"),
        }

    def _finish(self, state: dict, outcome: str) -> None:
        s = state["session"]
        state["history"] = (state.get("history") or [])[-19:] + [{
            "id": s["id"], "outcome": outcome, "finished_at": self.clock(),
            "stopped": s["stopped"], "failures": s["failures"],
        }]
        state["session"] = None

    # ------------------------------------------------------------------ prepare -------------
    def prepare(self, session_id: str) -> dict:
        if not SESSION_ID.match(session_id or ""):
            return self._result(False, "bad_session_id")
        with self.store.lock() as got:
            if not got:
                return self._result(False, "busy")
            state = self.store.load()
            cur = state["session"]
            if cur is not None:
                if cur["id"] == session_id and cur["phase"] in ("prepared", "stopping",
                                                                 "stopped"):
                    return self._result(True, "already_prepared", **self._public(cur))
                self.store.audit("prepare_rejected", session_id=session_id,
                                 active=cur["id"], phase=cur["phase"])
                return self._result(False, "session_active", active=cur["id"])
            if any(h["id"] == session_id for h in state.get("history", [])):
                return self._result(False, "session_id_reused")  # replay protection

            running: dict[str, object] = {}
            for name in self.policy.containers:
                info = self.docker.inspect(name)
                if info is not None and info.running:
                    running[name] = info

            skipped, blockers = [], []
            for name, info in running.items():
                rule = self.policy.containers[name]
                if rule.busy_probe is None:
                    continue
                busy, detail = self.run_probe(self.policy.probes[rule.busy_probe])
                if busy:
                    self.store.audit("busy", container=name, detail=detail, action=rule.on_busy)
                    if rule.on_busy == "block":
                        blockers.append({"container": name, "detail": detail})
                    else:
                        skipped.append({"container": name, "detail": detail})
            if blockers:
                return self._result(False, "blocked_busy", blockers=blockers)
            skipped_names = {s["container"] for s in skipped}
            to_stop = {n for n in running if n not in skipped_names}

            # Anything attached to a container we would stop must be part of the stop set,
            # otherwise stopping it would silently break an unlisted service (e.g. a
            # container using `network_mode: container:gluetun`).
            unexpected = []
            for other in self.docker.running():
                if other.name in to_stop:
                    continue
                for tname in to_stop:
                    tinfo = running[tname]
                    uses_ns = other.network_mode in (f"container:{tname}",
                                                     f"container:{tinfo.id}")
                    dep_label = tname in (other.labels.get("com.docker.compose.depends_on")
                                         or "")
                    if uses_ns or dep_label:
                        unexpected.append({"dependent": other.name, "depends_on": tname})
            if unexpected:
                self.store.audit("blocked_dependency", session_id=session_id,
                                 dependents=unexpected)
                return self._result(False, "blocked_dependency", dependents=unexpected)

            order = stop_order(self.policy.containers, to_stop)
            now = self.clock()
            state["session"] = {
                "id": session_id, "phase": "prepared", "created_at": now,
                "deadline": now + self.policy.max_session_seconds, "last_contact": now,
                "snapshot": [{"name": n, "id": running[n].id,
                              "restart_policy": running[n].restart_policy} for n in order],
                "stop_order": order, "stopped": [], "skipped": skipped, "failures": {},
                "mem_before": self.mem(), "mem_after": None, "stopping": None,
            }
            self.store.save(state)
            self.store.audit("prepared", session_id=session_id, stop_order=order,
                             skipped=skipped_names and sorted(skipped_names),
                             snapshot=state["session"]["snapshot"])
            return self._result(True, "prepared", **self._public(state["session"]))

    # ------------------------------------------------------------------ stop ----------------
    def stop_approved(self, session_id: str) -> dict:
        with self.store.lock() as got:
            if not got:
                return self._result(False, "busy")
            state = self.store.load()
            s = state["session"]
            if s is None or s["id"] != session_id:
                return self._result(False, "no_such_session")
            if s["phase"] not in ("prepared", "stopping", "stopped"):
                return self._result(False, "bad_phase", phase=s["phase"])
            if self.clock() >= s["deadline"]:
                return self._result(False, "deadline_passed")
            s["phase"], s["last_contact"] = "stopping", self.clock()
            self.store.save(state)
            for name in s["stop_order"]:
                if name in s["stopped"]:
                    continue
                rule = self.policy.containers[name]
                s["stopping"] = name
                self.store.save(state)                       # intent is durable BEFORE acting
                self.store.audit("stop", session_id=session_id, container=name)
                try:
                    self.docker.stop(name, rule.stop_timeout)
                    info = self.docker.inspect(name)
                    if info is not None and info.running:
                        raise DockerError("still running after stop")
                except DockerError as exc:
                    s["failures"][name] = f"stop: {exc}"
                    s["stopping"] = None
                    self.store.save(state)
                    self.store.audit("stop_failed", session_id=session_id, container=name,
                                     error=str(exc))
                    return self._result(False, "stop_failed", container=name,
                                        **self._public(s))
                s["stopped"].append(name)
                s["stopping"] = None
                self.store.save(state)
            s["phase"] = "stopped"
            s["mem_after"] = self.mem()
            self.store.save(state)
            self.store.audit("stopped", session_id=session_id, mem_after=s["mem_after"])
            if s["mem_after"] < self.policy.min_available_mib:
                return self._result(False, "insufficient_memory", **self._public(s))
            return self._result(True, "stopped", **self._public(s))

    # ------------------------------------------------------------------ restore -------------
    def _restore_locked(self, state: dict, reason: str) -> dict:
        s = state["session"]
        s["phase"] = "restoring"
        self.store.save(state)
        failures: dict[str, str] = {}
        # reverse of the stop order == dependencies first
        for entry in reversed(s["snapshot"]):
            name = entry["name"]
            if name not in self.policy.containers:       # policy changed under us: never touch
                failures[name] = "no longer in policy; not touched"
                continue
            try:
                info = self.docker.inspect(name)
                if info is None:
                    failures[name] = "missing (container was removed during the session)"
                    self.store.audit("restore_missing", container=name)
                    continue
                if info.id != entry["id"]:
                    self.store.audit("restore_recreated", container=name,
                                     old_id=entry["id"], new_id=info.id)
                if info.running:
                    continue
                self.store.audit("start", container=name, reason=reason)
                last: Exception | None = None
                for attempt in range(2):
                    try:
                        self.docker.start(name)
                        after = self.docker.inspect(name)
                        if after is not None and after.running:
                            last = None
                            break
                        last = DockerError("not running after start")
                    except DockerError as exc:
                        last = exc
                if last is not None:
                    raise last
            except DockerError as exc:
                failures[name] = f"start: {exc}"
                self.store.audit("start_failed", container=name, error=str(exc))
        s["failures"] = failures
        if failures:
            s["phase"] = "restore_failed"
            self.store.save(state)
            self.store.audit("restore_failed", session_id=s["id"], failures=failures)
            return self._result(False, "restore_failed", **self._public(s))
        sid = s["id"]
        self._finish(state, f"restored:{reason}")
        self.store.save(state)
        self.store.audit("restored", session_id=sid, reason=reason)
        return self._result(True, "restored", session_id=sid)

    def restore(self, session_id: str) -> dict:
        with self.store.lock() as got:
            if not got:
                return self._result(False, "busy")
            state = self.store.load()
            s = state["session"]
            if s is None:
                done = [h for h in state.get("history", []) if h["id"] == session_id]
                if done:
                    return self._result(True, "already_restored", session_id=session_id)
                return self._result(False, "no_such_session")
            if s["id"] != session_id:
                return self._result(False, "no_such_session", active=s["id"])
            s["last_contact"] = self.clock()
            return self._restore_locked(state, "restore")

    def emergency_restore(self) -> dict:
        with self.store.lock() as got:
            if not got:
                return self._result(False, "busy")
            state = self.store.load()
            if state["session"] is None:
                return self._result(True, "nothing_to_restore")
            self.store.audit("emergency_restore", session_id=state["session"]["id"])
            return self._restore_locked(state, "emergency")

    # ------------------------------------------------------------------ status --------------
    def status(self, session_id: str | None = None) -> dict:
        """Never blocks: reads the atomically-replaced state file. When the caller names
        the active session this doubles as the controller's liveness signal."""
        with self.store.lock(blocking=False) as got:
            state = self.store.load()
            s = state["session"]
            if got and s is not None and session_id and s["id"] == session_id:
                s["last_contact"] = self.clock()
                self.store.save(state)
            return self._result(True, "status", active=bool(s), operation_in_progress=not got,
                                session=self._public(s),
                                history=state.get("history", [])[-5:],
                                mem_available_mib=self.mem())

    # ------------------------------------------------------------------ watchdog ------------
    def watchdog_tick(self, at_boot: bool = False) -> dict:
        """Independent safety net, run by a separate systemd unit. Restores when the session
        outlived its deadline, the controller went silent, or after a reboot."""
        with self.store.lock(blocking=False) as got:
            if not got:
                return self._result(True, "operation_in_progress")
            state = self.store.load()
            s = state["session"]
            if s is None:
                return self._result(True, "idle")
            now = self.clock()
            reason = None
            if at_boot:
                reason = "boot_recovery"
            elif now >= s["deadline"]:
                reason = "deadline"
            elif s["phase"] == "restore_failed":
                reason = "retry_restore"
            elif s["phase"] == "restoring":
                # a previous restore was interrupted (helper killed mid-restore, we hold the
                # lock now, so nobody else is running it)
                reason = "restore_interrupted"
            elif s["phase"] in ("stopping", "stopped") and \
                    now - s["last_contact"] > self.policy.stale_contact_seconds:
                reason = "controller_silent"
            elif s["phase"] == "prepared" and \
                    now - s["created_at"] > self.policy.prepared_timeout_seconds:
                reason = "prepared_timeout"
            if reason is None:
                return self._result(True, "healthy", **self._public(s))
            self.store.audit("watchdog_restore", session_id=s["id"], reason=reason)
            res = self._restore_locked(state, f"watchdog:{reason}")
            res["reason"] = reason
            return res
