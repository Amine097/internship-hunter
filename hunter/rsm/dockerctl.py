"""Docker access. The broker needs only inspect/stop/start; each is a fixed argv list with a
validated container name. No shell, no `docker run/exec/rm/update/kill`, no restart-policy
changes: restart policies are therefore preserved by construction."""
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Protocol

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class DockerError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContainerInfo:
    id: str
    name: str
    running: bool
    restart_policy: str
    network_mode: str = ""
    labels: dict = field(default_factory=dict)


class DockerController(Protocol):
    def inspect(self, name: str) -> ContainerInfo | None: ...
    def stop(self, name: str, timeout: int) -> None: ...
    def start(self, name: str) -> None: ...
    def running(self) -> list[ContainerInfo]: ...


def _check(name: str) -> str:
    if not NAME.match(name):
        raise DockerError(f"invalid container name {name!r}")
    return name


class CliDocker:
    """Talks to the ROOTFUL daemon through the docker CLI as the broker's own user."""

    def __init__(self, docker_bin: str = "/usr/bin/docker", command_timeout: int = 200):
        self.bin, self.timeout = docker_bin, command_timeout

    def _run(self, *args: str, timeout: int | None = None) -> str:
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
               **({"DOCKER_HOST": os.environ["DOCKER_HOST"]} if "DOCKER_HOST" in os.environ
                  else {})}
        try:
            res = subprocess.run([self.bin, *args], capture_output=True, text=True, env=env,
                                 timeout=timeout or self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise DockerError(f"docker {args[0]} timed out") from exc
        if res.returncode != 0:
            raise DockerError(f"docker {args[0]} failed: {res.stderr.strip()[:200]}")
        return res.stdout

    @staticmethod
    def _parse(raw: dict) -> ContainerInfo:
        host = raw.get("HostConfig") or {}
        state = raw.get("State") or {}
        return ContainerInfo(
            id=raw.get("Id", ""), name=(raw.get("Name") or "").lstrip("/"),
            running=bool(state.get("Running")),
            restart_policy=(host.get("RestartPolicy") or {}).get("Name") or "no",
            network_mode=host.get("NetworkMode") or "",
            labels=(raw.get("Config") or {}).get("Labels") or {},
        )

    def inspect(self, name: str) -> ContainerInfo | None:
        _check(name)
        try:
            out = self._run("inspect", "--type", "container", name)
        except DockerError as exc:
            if "No such" in str(exc):
                return None
            raise
        data = json.loads(out)
        return self._parse(data[0]) if data else None

    def stop(self, name: str, timeout: int) -> None:
        self._run("stop", "--time", str(int(timeout)), _check(name), timeout=timeout + 30)

    def start(self, name: str) -> None:
        self._run("start", _check(name))

    def running(self) -> list[ContainerInfo]:
        ids = self._run("ps", "--no-trunc", "--format", "{{.ID}}").split()
        if not ids:
            return []
        data = json.loads(self._run("inspect", "--type", "container", *ids))
        return [self._parse(d) for d in data]
