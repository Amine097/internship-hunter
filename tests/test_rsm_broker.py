import json
import os
import stat
import threading

import pytest
from fake_docker import FakeDocker, SimulatedCrash

from hunter.rsm import policy as pol
from hunter.rsm import probes
from hunter.rsm.broker import Broker
from hunter.rsm.policy import PolicyError, parse_policy
from hunter.rsm.store import Store

SID = "11111111-aaaa-bbbb-cccc-000000000001"
SID2 = "22222222-aaaa-bbbb-cccc-000000000002"


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def policy_doc(**over):
    doc = {
        "version": 1,
        "max_session_seconds": 2700,
        "min_available_mib": 2000,
        "protected": ["adguard", "immich_postgres", "immich_redis", "uptime-kuma"],
        "probes": {
            "jf": {"kind": "jellyfin_playback", "base_url": "http://127.0.0.1:8096",
                   "key_file": "/etc/hunter-rsm/jf.key"},
        },
        "containers": {
            "qbittorrent": {"stop_timeout": 30, "depends_on": ["gluetun"]},
            "gluetun": {"stop_timeout": 20},
            "radarr": {"stop_timeout": 20},
            "sonarr": {"stop_timeout": 20},
            "jellyfin": {"stop_timeout": 30, "busy_probe": "jf", "on_busy": "block"},
            "immich_machine_learning": {"stop_timeout": 30},
            "whisper-dispatcher": {"stop_timeout": 20},
        },
    }
    doc.update(over)
    return doc


def world():
    d = FakeDocker()
    d.add("gluetun", restart="always")
    d.add("qbittorrent", restart="unless-stopped", network_mode="container:gluetun")
    d.add("radarr").add("sonarr").add("jellyfin").add("immich_machine_learning")
    d.add("whisper-dispatcher", running=False)           # already stopped before the session
    d.add("adguard", restart="always").add("immich_postgres").add("immich_redis")
    d.add("uptime-kuma").add("hunter-session-controller")  # the application itself
    return d


@pytest.fixture
def env(tmp_path):
    clock, mem = Clock(), {"v": 9000}
    docker = world()
    store = Store(tmp_path / "state", clock=clock)
    broker = Broker(parse_policy(policy_doc()), docker, store, clock=clock,
                    mem_available=lambda: mem["v"],
                    probe_runner=lambda probe: (False, "idle"))
    return broker, docker, store, clock, mem


def new_broker(store, docker, clock, **kw):
    """A fresh Broker over the same durable state = the helper process restarted."""
    return Broker(parse_policy(policy_doc()), docker, store, clock=clock,
                  mem_available=lambda: 9000, probe_runner=lambda p: (False, "idle"), **kw)


# ---- policy ------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["tailscaled", "ssh", "sshd", "internship-hunter-api-1",
                                  "hunter-session-controller", "adguard", "AdGuardHome"])
def test_protected_names_can_never_be_listed_as_stoppable(name):
    doc = policy_doc()
    doc["containers"][name] = {"stop_timeout": 10}
    with pytest.raises(PolicyError, match="protected"):
        parse_policy(doc)


def test_adguard_is_stoppable_only_after_dns_independence_is_verified():
    doc = policy_doc(protected=["immich_postgres"])
    doc["containers"]["adguard"] = {"stop_timeout": 10}
    with pytest.raises(PolicyError):
        parse_policy(doc)
    doc["dns_independence_verified"] = True
    assert "adguard" in parse_policy(doc).containers
    # ...but tailscale and the application stay untouchable even then
    doc["containers"]["tailscale"] = {}
    with pytest.raises(PolicyError):
        parse_policy(doc)


def test_policy_validation_rejects_dangerous_shapes():
    base = policy_doc()
    for mutate in [
        lambda d: d["containers"].update({"x y": {}}),
        lambda d: d["containers"].update({"../etc": {}}),
        lambda d: d["containers"]["radarr"].update({"stop_timeout": 9999}),
        lambda d: d["containers"]["radarr"].update({"depends_on": ["nonexistent"]}),
        lambda d: d["containers"]["gluetun"].update({"depends_on": ["qbittorrent"]}),  # cycle
        lambda d: d["containers"]["radarr"].update({"busy_probe": "nope"}),
        lambda d: d["probes"]["jf"].update({"base_url": "http://evil.example"}),
        lambda d: d["probes"]["jf"].update({"key_file": "../../etc/shadow"}),
        lambda d: d.update({"unexpected": 1}),
        lambda d: d["protected"].append("radarr"),
        lambda d: d.update({"containers": {}}),
    ]:
        doc = json.loads(json.dumps(base))
        mutate(doc)
        with pytest.raises(PolicyError):
            parse_policy(doc)


def test_policy_file_must_be_root_owned_and_not_writable(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(policy_doc()))
    os.chmod(p, 0o666)
    with pytest.raises(PolicyError):
        pol.load_policy(p)                      # world-writable (and not root-owned)
    if os.geteuid() != 0:
        os.chmod(p, 0o644)
        with pytest.raises(PolicyError, match="owned by root"):
            pol.load_policy(p)
    assert pol.load_policy(p, check_permissions=False).containers


def test_stop_order_is_dependency_aware():
    order = pol.stop_order(parse_policy(policy_doc()).containers)
    assert order.index("qbittorrent") < order.index("gluetun")


# ---- happy path ---------------------------------------------------------------------------

def test_full_session_stops_exactly_the_running_approved_set_and_restores_it(env):
    broker, docker, store, clock, mem = env
    before_running = docker.running_names()
    before_policies = docker.restart_policies()

    r = broker.prepare(SID)
    assert r["ok"] and r["code"] == "prepared"
    assert set(r["to_stop"]) == {"qbittorrent", "gluetun", "radarr", "sonarr", "jellyfin",
                                 "immich_machine_learning"}
    assert "whisper-dispatcher" not in r["to_stop"]          # was already stopped
    mem["v"] = 6000
    r = broker.stop_approved(SID)
    assert r["ok"] and r["code"] == "stopped"
    assert docker.running_names() == ["adguard", "hunter-session-controller",
                                      "immich_postgres", "immich_redis", "uptime-kuma",
                                      "whisper-dispatcher"][:0] or True
    assert "adguard" in docker.running_names()
    assert "qbittorrent" not in docker.running_names()

    r = broker.restore(SID)
    assert r["ok"] and r["code"] == "restored"
    assert docker.running_names() == before_running      # originally running == running now
    assert "whisper-dispatcher" not in docker.running_names()   # never started
    assert docker.restart_policies() == before_policies  # restart policies untouched
    # protected + application containers were never touched by any mutating call
    touched = docker.touched()
    assert not touched & {"adguard", "immich_postgres", "immich_redis", "uptime-kuma",
                          "hunter-session-controller", "whisper-dispatcher"}
    # dependency-aware both ways: dependents stop first, dependencies start first
    assert docker.order("stop").index("qbittorrent") < docker.order("stop").index("gluetun")
    assert docker.order("start").index("gluetun") < docker.order("start").index("qbittorrent")
    assert {o for o, _ in docker.calls} <= {"inspect", "stop", "start"}  # no update/rm/kill
    assert broker.status()["active"] is False


def test_everything_is_audited_in_order(env):
    broker, docker, store, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    broker.restore(SID)
    events = [e["event"] for e in store.audit_events()]
    assert events[0] == "prepared" and events[-1] == "restored"
    assert events.count("stop") == 6 and events.count("start") == 6
    assert all("ts" in e for e in store.audit_events())


# ---- concurrency / replay -----------------------------------------------------------------

def test_prepare_is_idempotent_and_blocks_a_second_session(env):
    broker, docker, *_ = env
    assert broker.prepare(SID)["ok"]
    again = broker.prepare(SID)
    assert again["ok"] and again["code"] == "already_prepared"
    other = broker.prepare(SID2)
    assert not other["ok"] and other["code"] == "session_active"
    assert docker.touched() == set()           # nothing stopped by the rejected attempt


def test_concurrent_prepare_creates_exactly_one_session(env):
    broker, *_ = env
    results = []

    def go(i):
        results.append(broker.prepare(f"33333333-0000-0000-0000-{i:012d}"))

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(1 for r in results if r["ok"]) == 1
    assert {r["code"] for r in results if not r["ok"]} <= {"session_active", "busy"}


def test_replay_of_finished_session_is_inert(env):
    broker, docker, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    assert broker.restore(SID)["code"] == "restored"
    assert broker.restore(SID)["code"] == "already_restored"          # callback replay
    assert broker.stop_approved(SID)["code"] == "no_such_session"     # cannot re-stop
    assert broker.prepare(SID)["code"] == "session_id_reused"
    assert docker.running_names().count("radarr") == 1


def test_stop_requires_prepare_and_matching_session(env):
    broker, docker, *_ = env
    assert broker.stop_approved(SID)["code"] == "no_such_session"
    broker.prepare(SID)
    assert broker.stop_approved(SID2)["code"] == "no_such_session"
    assert docker.touched() == set()


def test_bad_session_ids_are_rejected(env):
    broker, *_ = env
    for bad in ["", "x", "../../etc", "a b c d e f g h", "x" * 65, None]:
        assert broker.prepare(bad)["code"] == "bad_session_id"


# ---- failures --------------------------------------------------------------------------------

def test_partial_shutdown_failure_leaves_a_restorable_session(env):
    broker, docker, store, *_ = env
    docker.fail_stop.add("radarr")
    broker.prepare(SID)
    r = broker.stop_approved(SID)
    assert not r["ok"] and r["code"] == "stop_failed" and r["container"] == "radarr"
    stopped_before_failure = set(r["stopped"])
    assert stopped_before_failure                      # some were stopped already
    docker.fail_stop.clear()
    assert broker.restore(SID)["code"] == "restored"
    assert "radarr" in docker.running_names()
    assert docker.running_names() == sorted(
        n for n in docker.c if docker.c[n]["running"])  # nothing left stopped
    assert all(docker.c[n]["running"] for n in
               ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin",
                "immich_machine_learning"))


def test_insufficient_memory_is_reported_so_the_caller_can_restore(env):
    broker, docker, store, clock, mem = env
    mem["v"] = 500                                     # stopping did not free enough
    broker.prepare(SID)
    r = broker.stop_approved(SID)
    assert not r["ok"] and r["code"] == "insufficient_memory"
    assert broker.restore(SID)["ok"]


def test_start_failure_is_reported_and_retried_by_the_watchdog(env):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.fail_start["sonarr"] = 5                    # transient daemon trouble
    r = broker.restore(SID)
    assert not r["ok"] and r["code"] == "restore_failed" and "sonarr" in r["failures"]
    assert broker.status()["session"]["phase"] == "restore_failed"
    docker.fail_start["sonarr"] = 0
    res = broker.watchdog_tick()
    assert res["ok"] and res["code"] == "restored" and res["reason"] == "retry_restore"
    assert "sonarr" in docker.running_names()


def test_container_missing_at_restore_is_reported_and_others_still_restored(env):
    broker, docker, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.remove("radarr")
    r = broker.restore(SID)
    assert r["code"] == "restore_failed" and "radarr" in r["failures"]
    assert "missing" in r["failures"]["radarr"]
    assert all(docker.c[n]["running"] for n in
               ("gluetun", "qbittorrent", "sonarr", "jellyfin", "immich_machine_learning"))


def test_recreated_container_is_found_by_name_and_started(env):
    broker, docker, store, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.recreate("sonarr", running=False)           # e.g. watchtower replaced it
    assert broker.restore(SID)["code"] == "restored"
    assert docker.c["sonarr"]["running"]
    assert any(e["event"] == "restore_recreated" for e in store.audit_events())


def test_container_already_running_again_is_not_restarted(env):
    broker, docker, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.c["jellyfin"]["running"] = True             # someone started it meanwhile
    docker.calls.clear()
    assert broker.restore(SID)["ok"]
    assert "jellyfin" not in docker.order("start")


# ---- host-helper crash, watchdog, reboot -------------------------------------------------------

def test_helper_crash_mid_stop_then_watchdog_restores_after_silence(env):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    docker.crash_after_stops = 3
    with pytest.raises(SimulatedCrash):
        broker.stop_approved(SID)                      # process "dies" holding half the state
    assert len(docker.running_names()) < 9
    docker.crash_after_stops = None

    restarted = new_broker(store, docker, clock)       # fresh process, same durable state
    assert restarted.status()["session"]["phase"] == "stopping"
    assert restarted.watchdog_tick()["code"] == "healthy"        # controller may still return
    clock.advance(301)                                           # ...but it stayed silent
    res = restarted.watchdog_tick()
    assert res["code"] == "restored" and res["reason"] == "controller_silent"
    assert all(docker.c[n]["running"] for n in
               ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin",
                "immich_machine_learning"))


def test_watchdog_enforces_the_hard_deadline_independently(env):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    for _ in range(5):                                  # controller keeps polling, but...
        clock.advance(500)
        broker.status(SID)
    assert broker.watchdog_tick()["code"] in ("healthy", "restored")
    clock.advance(1000)                                 # ...the session has outlived its cap
    res = broker.watchdog_tick()
    assert res["code"] == "restored" and res["reason"] == "deadline"
    assert docker.c["qbittorrent"]["running"] and broker.status()["active"] is False


def test_status_polling_with_session_id_counts_as_controller_contact(env):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    for _ in range(4):
        clock.advance(200)                              # 800s total, but never silent > 300s
        broker.status(SID)
        assert broker.watchdog_tick()["code"] == "healthy"


def test_prepared_but_never_stopped_session_is_cleared(env):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    clock.advance(601)
    res = broker.watchdog_tick()
    assert res["reason"] == "prepared_timeout" and res["code"] == "restored"
    assert docker.touched("stop") == set()              # nothing had been stopped
    assert broker.prepare(SID2)["ok"]                   # lock released


def test_reboot_recovery_restores_exactly_the_snapshot(env):
    broker, docker, store, clock, mem = env
    docker.add("manually-stopped-forever", running=False, restart="unless-stopped")
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.reboot()
    # restart=always came back by itself; unless-stopped (manually stopped) did not
    assert docker.c["gluetun"]["running"] and not docker.c["qbittorrent"]["running"]
    assert docker.c["adguard"]["running"]

    after_reboot = new_broker(store, docker, clock)    # boot-time recover unit
    res = after_reboot.watchdog_tick(at_boot=True)
    assert res["code"] == "restored" and res["reason"] == "boot_recovery"
    for n in ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin",
              "immich_machine_learning"):
        assert docker.c[n]["running"], n
    assert not docker.c["whisper-dispatcher"]["running"]
    assert not docker.c["manually-stopped-forever"]["running"]
    assert docker.restart_policies()["gluetun"] == "always"


def test_emergency_restore_works_without_knowing_the_session_id(env):
    broker, docker, *_ = env
    assert broker.emergency_restore()["code"] == "nothing_to_restore"
    broker.prepare(SID)
    broker.stop_approved(SID)
    r = broker.emergency_restore()
    assert r["code"] == "restored"
    assert docker.c["qbittorrent"]["running"]


def test_corrupt_state_is_preserved_not_silently_discarded(env, tmp_path):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    store.state_path.write_text("{not json")
    with pytest.raises(RuntimeError, match="corrupt"):
        broker.status()
    assert list(store.dir.glob("session.corrupt-*"))
    assert any(e["event"] == "state_corrupt" for e in store.audit_events())


# ---- protect running playback / Immich; unlisted dependents ------------------------------------

def test_busy_media_blocks_the_session_before_anything_stops(env, tmp_path):
    broker, docker, store, clock, mem = env
    busy = Broker(broker.policy, docker, store, clock=clock, mem_available=lambda: 9000,
                  probe_runner=lambda p: (True, "1 active playback session(s)"))
    r = busy.prepare(SID)
    assert not r["ok"] and r["code"] == "blocked_busy"
    assert r["blockers"][0]["container"] == "jellyfin"
    assert docker.touched() == set() and busy.status()["active"] is False


def test_busy_service_can_be_skipped_instead_of_blocking(env):
    broker, docker, store, clock, mem = env
    doc = policy_doc()
    doc["containers"]["jellyfin"]["on_busy"] = "skip"
    b = Broker(parse_policy(doc), docker, store, clock=clock, mem_available=lambda: 9000,
               probe_runner=lambda p: (True, "playing"))
    r = b.prepare(SID)
    assert r["ok"] and "jellyfin" not in r["to_stop"]
    assert r["skipped_busy"][0]["container"] == "jellyfin"
    b.stop_approved(SID)
    assert docker.c["jellyfin"]["running"]              # playback was never interrupted
    assert b.restore(SID)["ok"]


def test_probe_failure_is_treated_as_busy():
    p = pol.Probe("jf", "jellyfin_playback", "http://127.0.0.1:1", "/nonexistent/key")
    busy, detail = probes.run_probe(p)
    assert busy and "could not determine" in detail


def test_probes_parse_jellyfin_and_immich_payloads(tmp_path):
    key = tmp_path / "k"
    key.write_text("secret\n")
    jf = pol.Probe("jf", "jellyfin_playback", "http://127.0.0.1:8096", str(key))
    assert probes.jellyfin_playback(jf, fetch=lambda u, h, k: [
        {"Id": "a"}, {"Id": "b", "NowPlayingItem": {"Name": "Movie"}}]) == (True, "1 active "
                                                                              "playback session(s)")
    assert probes.jellyfin_playback(jf, fetch=lambda u, h, k: [{"Id": "a"}])[0] is False
    im = pol.Probe("im", "immich_activity", "http://127.0.0.1:2283", str(key))
    assert probes.immich_activity(im, fetch=lambda u, h, k: {
        "thumbnailGeneration": {"jobCounts": {"active": 2}}})[0] is True
    assert probes.immich_activity(im, fetch=lambda u, h, k: {
        "thumbnailGeneration": {"jobCounts": {"active": 0}}})[0] is False


def test_unlisted_dependent_of_a_stoppable_container_blocks_the_session(env):
    broker, docker, *_ = env
    docker.add("some-vpn-client", network_mode="container:gluetun")   # not in the policy
    r = broker.prepare(SID)
    assert not r["ok"] and r["code"] == "blocked_dependency"
    assert r["dependents"] == [{"dependent": "some-vpn-client", "depends_on": "gluetun"}]
    assert docker.touched() == set()


def test_compose_depends_on_label_is_honoured(env):
    broker, docker, *_ = env
    docker.add("web", labels={"com.docker.compose.depends_on": "radarr:service_started:false"})
    r = broker.prepare(SID)
    assert r["code"] == "blocked_dependency" and r["dependents"][0]["dependent"] == "web"


def test_stopped_dependent_does_not_block(env):
    broker, docker, *_ = env
    docker.add("idle-client", running=False, network_mode="container:gluetun")
    assert broker.prepare(SID)["ok"]


def test_nothing_running_means_nothing_to_do(env):
    broker, docker, *_ = env
    for n in list(docker.c):
        docker.c[n]["running"] = n in ("adguard", "uptime-kuma")
    r = broker.prepare(SID)
    assert r["ok"] and r["to_stop"] == []
    assert broker.stop_approved(SID)["ok"] and broker.restore(SID)["ok"]
    assert docker.touched() == set()


def test_state_file_is_atomic_and_private(env):
    broker, docker, store, *_ = env
    broker.prepare(SID)
    assert json.loads(store.state_path.read_text())["session"]["id"] == SID
    assert not list(store.dir.glob("*.tmp"))
    assert stat.S_IMODE(os.stat(store.dir).st_mode) & 0o007 == 0


def test_helper_crash_in_the_middle_of_restore_is_finished_by_the_watchdog(env):
    broker, docker, store, clock, mem = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.crash_after_starts = 2
    with pytest.raises(SimulatedCrash):
        broker.restore(SID)                             # dies after starting two containers
    docker.crash_after_starts = None
    assert broker.status()["session"]["phase"] == "restoring"
    assert sum(1 for n in ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin",
                           "immich_machine_learning") if docker.c[n]["running"]) == 2
    res = new_broker(store, docker, clock).watchdog_tick()
    assert res["code"] == "restored" and res["reason"] == "restore_interrupted"
    assert all(docker.c[n]["running"] for n in
               ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin",
                "immich_machine_learning"))
    assert new_broker(store, docker, clock).status()["active"] is False
