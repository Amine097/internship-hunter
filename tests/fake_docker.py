"""In-memory Docker controller. Models what matters for restore correctness, including how
restart policies behave when the host reboots."""
import itertools

from hunter.rsm.dockerctl import ContainerInfo, DockerError


class SimulatedCrash(BaseException):
    """Raised from inside a Docker call to emulate the broker process dying mid-operation."""


class FakeDocker:
    def __init__(self):
        self.c: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.fail_stop: set[str] = set()
        self.fail_start: dict[str, int] = {}
        self.crash_after_stops: int | None = None
        self.crash_after_starts: int | None = None
        self._starts = 0
        self._ids = itertools.count(1)
        self._stops = 0

    # -- world construction ---------------------------------------------------------------
    def add(self, name, running=True, restart="unless-stopped", network_mode="", labels=None):
        self.c[name] = {"id": f"id{next(self._ids):04d}", "running": running,
                        "restart": restart, "network_mode": network_mode,
                        "labels": labels or {}, "manually_stopped": False}
        return self

    def recreate(self, name, running=False):
        old = self.c[name]
        self.c[name] = {**old, "id": f"id{next(self._ids):04d}", "running": running}

    def remove(self, name):
        del self.c[name]

    def reboot(self):
        """Host reboot: processes die; Docker restarts per policy on daemon start."""
        for v in self.c.values():
            was = v["running"]
            v["running"] = v["restart"] == "always" or (
                v["restart"] == "unless-stopped" and was and not v["manually_stopped"])

    def running_names(self):
        return sorted(n for n, v in self.c.items() if v["running"])

    def restart_policies(self):
        return {n: v["restart"] for n, v in self.c.items()}

    # -- DockerController ------------------------------------------------------------------
    def _info(self, name):
        v = self.c[name]
        return ContainerInfo(v["id"], name, v["running"], v["restart"], v["network_mode"],
                             dict(v["labels"]))

    def inspect(self, name):
        self.calls.append(("inspect", name))
        return self._info(name) if name in self.c else None

    def running(self):
        return [self._info(n) for n, v in self.c.items() if v["running"]]

    def stop(self, name, timeout):
        self.calls.append(("stop", name))
        if name not in self.c:
            raise DockerError("No such container")
        if name in self.fail_stop:
            raise DockerError("stop timed out")
        self.c[name]["running"] = False
        self.c[name]["manually_stopped"] = True
        self._stops += 1
        if self.crash_after_stops is not None and self._stops >= self.crash_after_stops:
            raise SimulatedCrash

    def start(self, name):
        self.calls.append(("start", name))
        if name not in self.c:
            raise DockerError("No such container")
        if self.fail_start.get(name, 0) > 0:
            self.fail_start[name] -= 1
            raise DockerError("start failed")
        self.c[name]["running"] = True
        self.c[name]["manually_stopped"] = False
        self._starts += 1
        if self.crash_after_starts is not None and self._starts >= self.crash_after_starts:
            raise SimulatedCrash

    # -- assertions helpers ------------------------------------------------------------------
    def touched(self, op=None):
        return {n for o, n in self.calls if o != "inspect" and (op is None or o == op)}

    def order(self, op):
        return [n for o, n in self.calls if o == op]
