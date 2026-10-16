"""Fixes for the independent review of 9d35464: dependency discovery (MEDIUM-2), admin
recovery (MEDIUM-3), slow stops (MEDIUM-4), corrupt state / invalid policy (LOW-1)."""
import json
import os
import stat
import subprocess
import sys
import threading

import pytest
from fake_docker import FakeDocker
from test_rsm_broker import SID, SID2, Clock, new_broker, policy_doc, world

from hunter.rsm import admin
from hunter.rsm import notify as notify_mod
from hunter.rsm.broker import Broker
from hunter.rsm.policy import PolicyError, parse_policy
from hunter.rsm.server import handle_request
from hunter.rsm.store import Store

MANAGED = ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin", "immich_machine_learning")


@pytest.fixture
def env(tmp_path):
    clock, docker = Clock(), world()
    store = Store(tmp_path / "state", clock=clock)
    broker = Broker(parse_policy(policy_doc()), docker, store, clock=clock,
                    mem_available=lambda: 9000, probe_runner=lambda p: (False, "idle"))
    return broker, docker, store, clock


# ---- MEDIUM-2: real NetworkMode=container:<id> dependencies ------

def test_real_namespace_edge_must_be_declared_in_the_policy(env):
    _, docker, store, clock = env
    doc = policy_doc()
    doc["containers"]["qbittorrent"].pop("depends_on")      # operator forgot the edge
    b = Broker(parse_policy(doc), docker, store, clock=clock, mem_available=lambda: 9000,
               probe_runner=lambda p: (False, "idle"))
    r = b.prepare(SID)
    assert not r["ok"] and r["code"] == "blocked_dependency"
    assert r["problems"] == [{"code": "undeclared_dependency", "client": "qbittorrent",
                              "provider": "gluetun"}]
    assert docker.touched() == set() and b.status()["active"] is False


def test_declared_edge_orders_clients_before_providers_and_back(env):
    broker, docker, *_ = env
    assert broker.prepare(SID)["ok"]
    broker.stop_approved(SID)
    broker.restore(SID)
    assert docker.order("stop").index("qbittorrent") < docker.order("stop").index("gluetun")
    assert docker.order("start").index("gluetun") < docker.order("start").index("qbittorrent")


def test_name_form_and_id_form_references_are_both_resolved(env):
    broker, docker, *_ = env
    docker.add("sidecar", uses_netns_of="gluetun", ref="name")   # container:gluetun
    r = broker.prepare(SID)
    assert r["code"] == "blocked_dependency"
    assert {"code": "unlisted_dependent", "dependent": "sidecar",
            "depends_on": "gluetun"} in r["problems"]


def test_provider_with_a_new_container_id_is_detected_as_stale(env):
    broker, docker, *_ = env
    docker.recreate("gluetun", running=True)                     # client keeps the OLD id
    r = broker.prepare(SID)
    assert r["code"] == "blocked_dependency"
    assert r["problems"][0]["code"] == "stale_provider"
    assert r["problems"][0]["client"] == "qbittorrent"
    assert docker.touched() == set()


def test_ambiguous_reference_is_refused(env):
    broker, docker, *_ = env
    docker.c["qbittorrent"]["network_mode"] = "container:0000000000"   # prefix of many ids
    r = broker.prepare(SID)
    assert r["code"] == "blocked_dependency"
    assert r["problems"][0]["code"] == "ambiguous_provider"
    assert docker.touched() == set()


def test_busy_skipped_client_of_a_stopping_provider_blocks_the_session(env):
    _, docker, store, clock = env
    docker.add("radarr2", uses_netns_of="gluetun")
    doc = policy_doc()
    doc["probes"]["rd"] = {"kind": "jellyfin_playback", "base_url": "http://127.0.0.1:8096",
                           "key_file": "/etc/hunter-rsm/jf.key"}
    doc["containers"]["radarr2"] = {"stop_timeout": 20, "depends_on": ["gluetun"],
                                    "busy_probe": "rd", "on_busy": "skip"}
    busy_for = {"rd"}
    b = Broker(parse_policy(doc), docker, store, clock=clock, mem_available=lambda: 9000,
               probe_runner=lambda p: (p.name in busy_for, "busy"))
    r = b.prepare(SID)
    assert r["code"] == "blocked_dependency"          # radarr2 would lose its network
    assert {"code": "unlisted_dependent", "dependent": "radarr2",
            "depends_on": "gluetun"} in r["problems"]


def test_provider_recreated_during_the_session_is_reported_not_retried_blindly(env):
    broker, docker, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.recreate("gluetun", running=False)         # e.g. an auto-updater replaced it
    docker.calls.clear()
    r = broker.restore(SID)
    assert r["code"] == "restore_failed"
    assert "recreated" in r["failures"]["qbittorrent"]
    assert "qbittorrent" not in docker.order("start")           # never attempted
    assert docker.c["gluetun"]["running"]                       # the provider itself came back
    for n in ("radarr", "sonarr", "jellyfin", "immich_machine_learning"):
        assert docker.c[n]["running"]
    assert any(e["event"] == "restore_provider_problem" for e in broker.store.audit_events())


def test_provider_not_running_at_restore_is_a_clear_failure(env):
    broker, docker, *_ = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.fail_start["gluetun"] = 99                           # provider cannot start
    r = broker.restore(SID)
    assert r["code"] == "restore_failed"
    assert "gluetun" in r["failures"] and "not running" in r["failures"]["qbittorrent"]


def test_snapshot_records_the_provider(env):
    broker, docker, *_ = env
    r = broker.prepare(SID)
    entry = next(e for e in broker.store.load()["session"]["snapshot"]
                 if e["name"] == "qbittorrent")
    assert entry["provider"] == {"name": "gluetun", "id": docker.c["gluetun"]["id"]}
    assert r["ok"]


# ---- MEDIUM-4: slow shutdowns ------

def test_slow_stops_do_not_make_the_session_look_silent(env):
    broker, docker, store, clock = env
    watchdog = new_broker(store, docker, clock)
    seen = []

    def slow(name):
        clock.advance(200)                                      # each stop takes 200 s
        seen.append(watchdog.watchdog_tick()["code"])           # watchdog fires mid-stop

    docker.on_stop = slow
    broker.prepare(SID)
    r = broker.stop_approved(SID)
    assert r["ok"] and len(seen) == 6
    assert set(seen) == {"operation_in_progress"}               # lock held: never restores
    clock.advance(0)
    after = watchdog.watchdog_tick()                            # the instant the op returns
    assert after["code"] == "healthy", after                    # 1200 s elapsed, contact fresh
    assert all(not docker.c[n]["running"] for n in MANAGED)     # nothing was restored early


def test_slow_stops_with_old_semantics_would_have_been_restored(env):
    """Guards the fix itself: contact is refreshed per stop, so a 1200 s phase reads as fresh."""
    broker, docker, store, clock = env
    docker.on_stop = lambda n: clock.advance(250)
    broker.prepare(SID)
    broker.stop_approved(SID)
    s = store.load()["session"]
    assert clock() - s["last_contact"] < 60
    clock.advance(299)
    assert new_broker(store, docker, clock).watchdog_tick()["code"] == "healthy"
    clock.advance(2)
    assert new_broker(store, docker, clock).watchdog_tick()["reason"] == "controller_silent"


def test_stale_contact_is_validated_against_the_slowest_single_stop():
    doc = policy_doc(stale_contact_seconds=100)
    doc["containers"]["radarr"]["stop_timeout"] = 120           # single stop budget 150 s
    with pytest.raises(PolicyError, match="stale_contact_seconds"):
        parse_policy(doc)
    ok = policy_doc(stale_contact_seconds=210)
    ok["containers"]["radarr"]["stop_timeout"] = 120
    assert parse_policy(ok).max_single_stop_seconds() == 150


def test_budgets_are_exposed_so_client_deadlines_can_exceed_them(env):
    broker, *_ = env
    lim = broker.prepare(SID)["limits"]
    pol = broker.policy
    assert lim["stop_phase_budget_seconds"] == sum(c.stop_timeout + 30
                                                   for c in pol.containers.values())
    assert lim["stale_contact_seconds"] > lim["max_single_stop_seconds"]
    assert lim["stop_phase_budget_seconds"] * 2 < lim["max_session_seconds"]


# ---- MEDIUM-3: root-only administrative recovery ------

def stuck_session(env):
    broker, docker, store, clock = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.remove("radarr")                                     # gone for good
    assert broker.restore(SID)["code"] == "restore_failed"
    return broker, docker, store, clock


def test_abandon_records_unresolved_services_and_releases_the_session(env):
    broker, docker, store, clock = stuck_session(env)
    before = store.audit_events()
    res = admin.abandon(broker, "radarr container was deleted permanently by the owner")
    assert res["code"] == "abandoned"
    assert [u["container"] for u in res["unresolved"]] == ["radarr"]
    assert res["unresolved"][0]["state"] == "missing" and "missing" in res["unresolved"][0][
        "failure"]
    assert broker.status()["active"] is False
    last = store.load()["history"][-1]
    assert last["outcome"] == "abandoned" and "deleted permanently" in last["reason"]
    assert last["unresolved"] and "uid=" in last["operator"]
    events = store.audit_events()
    assert events[: len(before)] == before                      # audit trail only ever grows
    assert events[-1]["event"] == "abandoned"
    assert broker.prepare(SID2)["ok"]                           # the host is usable again


def test_abandon_never_touches_containers(env):
    broker, docker, *_ = stuck_session(env)
    docker.calls.clear()
    admin.abandon(broker, "owner accepted that radarr is lost for good")
    assert docker.touched() == set()


def test_abandon_requires_a_real_reason_a_stuck_session_and_an_active_session(env):
    broker, docker, store, clock = env
    with pytest.raises(admin.AdminError, match="no active session"):
        admin.abandon(broker, "nothing to abandon here at all")
    broker.prepare(SID)
    with pytest.raises(admin.AdminError, match="phase 'prepared'"):
        admin.abandon(broker, "trying to abandon a healthy session")
    with pytest.raises(admin.AdminError, match="reason"):
        admin.abandon(broker, "short", force=True)
    assert broker.status()["active"] is True


def test_reconcile_retries_the_restore_on_admin_authority(env):
    broker, docker, store, clock = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.fail_start["sonarr"] = 2                 # beats the broker's own two attempts
    assert broker.restore(SID)["code"] == "restore_failed"
    res = admin.reconcile(broker)
    assert res["code"] == "restored" and docker.c["sonarr"]["running"]
    assert any(e["event"] == "admin_reconcile" for e in store.audit_events())


@pytest.mark.parametrize("op", ["abandon", "reconcile", "admin", "recover_state",
                                "recover-state", "show"])
def test_admin_operations_are_not_reachable_over_the_untrusted_socket(env, op):
    broker, docker, *_ = env
    assert handle_request(broker, json.dumps({"op": op, "reason": "x" * 20}).encode())[
        "ok"] is False
    assert handle_request(broker, json.dumps({"op": op}).encode())["code"] == \
        "unknown_operation"
    assert docker.calls == []


FAKE_DOCKER_SCRIPT = """#!/bin/sh
echo "$@" >> "$FAKE_DOCKER_LOG"
case "$1" in
  inspect) echo "Error: No such container: $4" >&2; exit 1;;
  ps) exit 0;;
esac
exit 0
"""


def cli(args, tmp_path, policy_doc_=None, extra_env=None):
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps(policy_doc_ or policy_doc()))
    fake = tmp_path / "docker"
    fake.write_text(FAKE_DOCKER_SCRIPT)
    fake.chmod(0o755)
    log = tmp_path / "docker.log"
    env = {**os.environ, "FAKE_DOCKER_LOG": str(log), **(extra_env or {})}
    proc = subprocess.run(
        [sys.executable, "-m", "hunter.rsm", *args, "--policy", str(pol),
         "--state-dir", str(tmp_path / "state"), "--docker-bin", str(fake),
         "--insecure-policy-permissions"],
        capture_output=True, text=True, env=env, timeout=60)
    return proc, log


def test_admin_cli_refuses_non_root(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    proc, log = cli(["admin", "abandon", "--reason", "a long enough reason here"], tmp_path)
    assert proc.returncode == 5 and "must run as root" in proc.stderr
    assert not log.exists()                                      # no Docker call at all
    for sub in (["admin", "show"], ["admin", "reconcile"],
                ["admin", "recover-state", "--mode", "backup", "--reason", "x" * 20]):
        assert cli(sub, tmp_path)[0].returncode == 5


def test_admin_cli_works_for_root_equivalent_flag_and_audits(tmp_path):
    store = Store(tmp_path / "state")
    state = {"version": 1, "history": [], "session": {
        "id": SID, "phase": "restore_failed", "created_at": 0, "deadline": 9e9,
        "last_contact": 0, "snapshot": [{"name": "radarr", "id": "x", "restart_policy": "no"}],
        "stop_order": ["radarr"], "stopped": ["radarr"], "skipped": [],
        "failures": {"radarr": "start: gone"}}}
    store.save(state)
    proc, _ = cli(["admin", "abandon", "--reason", "radarr was removed by the owner",
                   "--insecure-no-root-check"], tmp_path)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["code"] == "abandoned" and out["unresolved"][0]["container"] == "radarr"
    assert Store(tmp_path / "state").load()["session"] is None


# ---- alert rate limiting --------------------

def test_alert_due_rate_limits_per_key(tmp_path):
    clock = Clock()
    s = Store(tmp_path, clock=clock)
    assert s.alert_due("k", 1800) is True
    assert s.alert_due("k", 1800) is False
    assert s.alert_due("other", 1800) is True
    clock.advance(1801)
    assert s.alert_due("k", 1800) is True


def test_watchdog_cli_alerts_once_per_interval_while_restore_keeps_failing(
        env, monkeypatch, tmp_path):
    broker, docker, store, clock = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    docker.fail_start["sonarr"] = 10_000
    assert broker.restore(SID)["code"] == "restore_failed"      # now the watchdog retries
    sent = []
    monkeypatch.setattr(notify_mod, "send", lambda n, text, **k: sent.append(text) or True)
    from hunter.rsm import __main__ as cli_main
    monkeypatch.setattr(cli_main, "build", lambda args: broker)
    for _ in range(6):
        assert cli_main.main(["watchdog", "--insecure-policy-permissions"]) == 2
    assert len([t for t in sent if "RESTORE FAILED" in t]) == 1
    clock.advance(1801)
    cli_main.main(["watchdog"])
    assert len([t for t in sent if "RESTORE FAILED" in t]) == 2


# ---- LOW-1: corrupt state / invalid policy, with the administrator in control ------

def corrupt_with_backup(env):
    broker, docker, store, clock = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    store.state_path.write_text("{truncated")
    return broker, docker, store, clock


def test_recover_from_backup_preserves_evidence_and_restores_the_snapshot(env):
    broker, docker, store, clock = corrupt_with_backup(env)
    assert broker.status()["code"] == "state_corrupt"
    res = admin.recover_state(broker, "backup", "state was truncated by a full disk")
    assert res["code"] == "recovered_from_backup"
    assert set(res["must_restore"]) == set(MANAGED)
    evidence = [p for p in store.dir.glob("session.json.corrupt-*")]
    assert len(evidence) == 1 and evidence[0].read_text() == "{truncated"
    assert broker.status()["active"] is True                    # session is visible again
    assert broker.watchdog_tick(at_boot=True)["code"] == "restored"
    assert all(docker.c[n]["running"] for n in MANAGED)
    assert any(e["event"] == "state_recovered_from_backup" for e in store.audit_events())


def test_discard_requires_explicit_verification_and_keeps_the_evidence(env):
    broker, docker, store, clock = corrupt_with_backup(env)
    with pytest.raises(admin.AdminError, match="containers-verified"):
        admin.recover_state(broker, "discard", "backup is also unusable, verified by hand")
    assert broker.status()["code"] == "state_corrupt"           # still loud
    res = admin.recover_state(broker, "discard", "all containers verified running manually",
                              containers_verified=True)
    assert res["code"] == "discarded"
    assert next(store.dir.glob("session.json.corrupt-*")).read_text() == "{truncated"
    assert broker.status()["active"] is False


def test_recover_refuses_when_nothing_is_wrong_or_no_backup_exists(env):
    broker, docker, store, clock = env
    with pytest.raises(admin.AdminError, match="readable"):
        admin.recover_state(broker, "backup", "nothing is wrong with the state")
    store.state_path.write_text("junk")
    with pytest.raises(admin.AdminError, match="no valid backup"):
        admin.recover_state(broker, "backup", "attempting recovery without a backup")
    assert store.state_path.read_text() == "junk"               # untouched


def test_show_never_raises_on_corruption(env):
    broker, docker, store, clock = corrupt_with_backup(env)
    out = admin.show(broker)
    assert "state_error" in out and out["state_raw"] == "{truncated"
    assert out["backup"]["session"]["id"] == SID


def test_invalid_policy_is_loud_and_nothing_is_touched(tmp_path):
    doc = policy_doc()
    doc["containers"]["adguard"] = {"stop_timeout": 10}          # protected name
    for command in (["watchdog"], ["recover"], ["serve", "--socket", str(tmp_path / "s.sock")],
                    ["status"]):
        proc, log = cli(command, tmp_path, policy_doc_=doc)
        assert proc.returncode == 4, command
        assert json.loads(proc.stderr)["code"] == "invalid_policy"
        assert "protected" in proc.stderr
        assert not log.exists()                                  # never reached Docker


def test_policy_file_edited_after_a_session_started_cannot_widen_what_restore_touches(env):
    broker, docker, store, clock = env
    broker.prepare(SID)
    broker.stop_approved(SID)
    smaller = policy_doc()
    del smaller["containers"]["radarr"]
    b2 = Broker(parse_policy(smaller), docker, store, clock=clock, mem_available=lambda: 9000)
    r = b2.restore(SID)
    assert r["code"] == "restore_failed" and "radarr" in r["failures"]
    assert not docker.c["radarr"]["running"]                     # not in policy: not touched


def test_state_files_are_not_world_accessible(env):
    broker, docker, store, clock = env
    broker.prepare(SID)
    assert stat.S_IMODE(os.stat(store.dir).st_mode) & 0o007 == 0
    assert stat.S_IMODE(os.stat(store.audit_path).st_mode) & 0o007 == 0
    assert threading and FakeDocker                              # keep imports referenced
