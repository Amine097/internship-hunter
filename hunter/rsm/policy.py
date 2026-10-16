"""Administrator-approved policy. The ONLY source of container names the broker may touch."""
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SESSION_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")

# Hard-coded in CODE so that no policy file can ever make these stoppable.
ALWAYS_PROTECTED = (
    re.compile(r"tailscale", re.I),
    re.compile(r"^ssh", re.I),
    re.compile(r"internship[-_]?hunter", re.I),   # the application's own project
    re.compile(r"^hunter", re.I),
)
DNS_PROTECTED = re.compile(r"adguard", re.I)       # protected until DNS independence verified
PROBE_KINDS = ("jellyfin_playback", "immich_activity")
ON_BUSY = ("skip", "block")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ContainerRule:
    name: str
    stop_timeout: int = 30
    depends_on: tuple[str, ...] = ()   # X depends_on Y: stop X before Y, start Y before X
    busy_probe: str | None = None
    on_busy: str = "block"


@dataclass(frozen=True)
class Probe:
    name: str
    kind: str
    base_url: str
    key_file: str


@dataclass(frozen=True)
class Notify:
    bot_token_file: str
    chat_id: int
    api_base: str = "https://api.telegram.org"


@dataclass(frozen=True)
class Policy:
    containers: dict[str, ContainerRule]
    protected: frozenset[str]
    probes: dict[str, Probe] = field(default_factory=dict)
    max_session_seconds: int = 2700
    stale_contact_seconds: int = 300
    prepared_timeout_seconds: int = 600
    min_available_mib: int = 3072
    dns_independence_verified: bool = False
    notify: Notify | None = None

    def max_single_stop_seconds(self) -> int:
        """Longest a SINGLE stop may take: docker's own wait plus the CLI's 30 s slack."""
        return max(c.stop_timeout for c in self.containers.values()) + 30

    def stop_phase_budget(self) -> int:
        """Upper bound for a whole stop_approved call (every container, slack included)."""
        return sum(c.stop_timeout + 30 for c in self.containers.values())

    def limits(self) -> dict:
        return {"stop_phase_budget_seconds": self.stop_phase_budget(),
                "max_single_stop_seconds": self.max_single_stop_seconds(),
                "stale_contact_seconds": self.stale_contact_seconds,
                "max_session_seconds": self.max_session_seconds}


def is_always_protected(name: str, dns_verified: bool = False) -> bool:
    if any(p.search(name) for p in ALWAYS_PROTECTED):
        return True
    return bool(DNS_PROTECTED.search(name)) and not dns_verified


def _check_file_security(path: Path) -> None:
    st = path.stat()
    if st.st_uid != 0:
        raise PolicyError(f"{path} must be owned by root (uid {st.st_uid})")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PolicyError(f"{path} must not be group- or world-writable")


def parse_policy(doc: dict) -> Policy:
    if doc.get("version") != 1:
        raise PolicyError("unsupported policy version")
    unknown = set(doc) - {"version", "containers", "protected", "probes", "max_session_seconds",
                          "stale_contact_seconds", "prepared_timeout_seconds",
                          "min_available_mib", "dns_independence_verified", "telegram_notify",
                          "_comment"}
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
    dns_ok = doc.get("dns_independence_verified", False)
    if not isinstance(dns_ok, bool):
        raise PolicyError("dns_independence_verified must be a boolean")

    probes = {}
    for pname, raw in (doc.get("probes") or {}).items():
        if not NAME.match(pname) or raw.get("kind") not in PROBE_KINDS:
            raise PolicyError(f"bad probe {pname!r}")
        url = raw.get("base_url", "")
        if not re.match(r"^http://(127\.0\.0\.1|localhost|\[::1\]|10\.\d+\.\d+\.\d+|"
                        r"192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?$", url):
            raise PolicyError(f"probe {pname!r}: base_url must be plain http to a local address")
        key = raw.get("key_file", "")
        if not key.startswith("/") or ".." in key:
            raise PolicyError(f"probe {pname!r}: key_file must be an absolute path")
        probes[pname] = Probe(pname, raw["kind"], url, key)

    containers: dict[str, ContainerRule] = {}
    for name, raw in (doc.get("containers") or {}).items():
        if not NAME.match(name):
            raise PolicyError(f"invalid container name {name!r}")
        if is_always_protected(name, dns_ok):
            raise PolicyError(f"{name!r} is protected and can never be stoppable")
        timeout = raw.get("stop_timeout", 30)
        if not isinstance(timeout, int) or not 1 <= timeout <= 120:
            raise PolicyError(f"{name}: stop_timeout must be 1..120")
        probe = raw.get("busy_probe")
        if probe is not None and probe not in probes:
            raise PolicyError(f"{name}: unknown busy_probe {probe!r}")
        on_busy = raw.get("on_busy", "block")
        if on_busy not in ON_BUSY:
            raise PolicyError(f"{name}: on_busy must be one of {ON_BUSY}")
        deps = tuple(raw.get("depends_on", ()))
        containers[name] = ContainerRule(name, timeout, deps, probe, on_busy)
    if not containers:
        raise PolicyError("policy lists no stoppable containers")
    if len(containers) > 40:
        raise PolicyError("too many containers")

    protected = frozenset(doc.get("protected", ()))
    for name in protected:
        if not NAME.match(name):
            raise PolicyError(f"invalid protected name {name!r}")
    both = protected & set(containers)
    if both:
        raise PolicyError(f"names both protected and stoppable: {sorted(both)}")
    for c in containers.values():
        for dep in c.depends_on:
            if dep not in containers and dep not in protected:
                raise PolicyError(f"{c.name} depends_on unknown container {dep!r}")
    _topological_order(containers)  # raises on cycles

    notify = None
    if doc.get("telegram_notify"):
        n = doc["telegram_notify"]
        notify = Notify(n["bot_token_file"], int(n["chat_id"]),
                        n.get("api_base", "https://api.telegram.org"))
    pol = Policy(
        containers=containers, protected=protected, probes=probes,
        max_session_seconds=int(doc.get("max_session_seconds", 2700)),
        stale_contact_seconds=int(doc.get("stale_contact_seconds", 300)),
        prepared_timeout_seconds=int(doc.get("prepared_timeout_seconds", 600)),
        min_available_mib=int(doc.get("min_available_mib", 3072)),
        dns_independence_verified=dns_ok, notify=notify,
    )
    if not 60 <= pol.max_session_seconds <= 4 * 3600:
        raise PolicyError("max_session_seconds must be 60..14400")
    if pol.stop_phase_budget() * 2 >= pol.max_session_seconds:
        raise PolicyError("sum of stop timeouts is too large for max_session_seconds")
    # The broker refreshes last_contact after every single stop, so staleness is measured
    # against ONE stop, never the whole phase: it must comfortably exceed the slowest stop.
    if pol.stale_contact_seconds < pol.max_single_stop_seconds() + 60:
        raise PolicyError(
            f"stale_contact_seconds ({pol.stale_contact_seconds}) must be at least "
            f"{pol.max_single_stop_seconds() + 60} (slowest single stop + 60 s margin)")
    if pol.prepared_timeout_seconds < 60:
        raise PolicyError("prepared_timeout_seconds must be at least 60")
    return pol


def _start_order(containers: dict[str, ContainerRule]) -> list[str]:
    """Dependencies first (X depends_on Y => Y appears before X). Raises on cycles."""
    order: list[str] = []
    state: dict[str, int] = {}

    def visit(n: str) -> None:
        if state.get(n) == 2:
            return
        if state.get(n) == 1:
            raise PolicyError(f"dependency cycle through {n!r}")
        state[n] = 1
        for dep in containers[n].depends_on:
            if dep in containers:       # protected deps are never stopped, so never ordered
                visit(dep)
        state[n] = 2
        order.append(n)

    for n in containers:
        visit(n)
    return order


def _topological_order(containers: dict[str, ContainerRule]) -> list[str]:
    return _start_order(containers)


def stop_order(containers: dict[str, ContainerRule], subset: set[str] | None = None) -> list[str]:
    """Dependents before the things they depend on (exact reverse of the start order)."""
    return [n for n in reversed(_start_order(containers)) if subset is None or n in subset]


def load_policy(path: str | Path, check_permissions: bool = True) -> Policy:
    p = Path(path)
    if check_permissions:
        _check_file_security(p)
        _check_file_security(p.parent)
    try:
        doc = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read policy: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a JSON object")
    return parse_policy(doc)


def ensure_owner_only(path: str | Path) -> None:
    """Helper for key files: refuse world-readable secrets."""
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PolicyError(f"{path} must not be group/world accessible")
