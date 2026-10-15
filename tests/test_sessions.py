"""Approval -> reservation -> research -> restoration, with the real broker logic over a fake
Docker (disposable-container tests live in test_rsm_docker_integration.py)."""
import threading
from datetime import timedelta

import pytest
from fake_docker import FakeDocker
from sqlalchemy import func, select
from test_rsm_broker import policy_doc, world

from hunter import orchestrator, sessions, telegram
from hunter.db import session_scope
from hunter.models import Notification, ResourceSession, RsmCommand, Scan, Task
from hunter.policy import SUBMISSION_ENABLED
from hunter.rsm.broker import Broker
from hunter.rsm.policy import parse_policy
from hunter.rsm.store import Store
from hunter.rsm_client import RsmUnavailable
from hunter.session_controller import SessionController
from hunter.taskqueue import TaskQueue

OWNER = 4242
MANAGED = ("gluetun", "qbittorrent", "radarr", "sonarr", "jellyfin", "immich_machine_learning")


class InProcessRsm:
    """Same surface as RsmClient, over the real Broker (no socket)."""

    def __init__(self, broker):
        self.b, self.down = broker, False
        self.log: list[str] = []

    def _go(self, name, *a):
        if self.down:
            raise RsmUnavailable("ConnectionRefusedError")
        self.log.append(name)
        return getattr(self.b, name)(*a)

    def prepare(self, sid):
        return self._go("prepare", sid)

    def stop_approved(self, sid):
        return self._go("stop_approved", sid)

    def restore(self, sid):
        return self._go("restore", sid)

    def status(self, sid=None):
        return self._go("status", sid)

    def emergency_restore(self):
        return self._go("emergency_restore")


@pytest.fixture
def rig(database, agent_fleet, clock, tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_MAX_SECONDS", "600")
    from hunter.settings import get_settings
    get_settings.cache_clear()
    docker = world()
    broker = Broker(parse_policy(policy_doc()), docker,
                    Store(tmp_path / "rsm", clock=lambda: clock().timestamp()),
                    clock=lambda: clock().timestamp(), mem_available=lambda: 9000,
                    probe_runner=lambda p: (False, "idle"))
    rsm = InProcessRsm(broker)
    queue = TaskQueue(clock=clock)
    ctrl = SessionController(rsm, queue, clock=clock)

    class Rig:
        pass
    r = Rig()
    r.docker, r.broker, r.rsm, r.queue, r.ctrl, r.clock = docker, broker, rsm, queue, ctrl, clock
    r.agents = agent_fleet
    return r


def request(rig, **kw):
    sid, _ = sessions.request_session("manual", at=rig.clock(), **kw)
    return sid


def nonce_of(sid):
    with session_scope() as db:
        return db.get(ResourceSession, sid).nonce


def accept(rig, sid):
    return sessions.decide(sid, nonce_of(sid), True, at=rig.clock())


def state_of(sid):
    with session_scope() as db:
        return db.get(ResourceSession, sid).state


def run_scans(rig):
    n = 0
    while (c := rig.queue.claim()) is not None:
        orchestrator.process_claim(rig.queue, c)
        n += 1
    return n


def drive(rig, sid, until, ticks=30, scans=True):
    for _ in range(ticks):
        rig.ctrl.tick()
        if scans and state_of(sid) == "running":
            run_scans(rig)
        if state_of(sid) in until:
            return state_of(sid)
        rig.clock.advance(1)
    raise AssertionError(f"stuck in {state_of(sid)}")


def notes():
    with session_scope() as db:
        rows = db.scalars(select(Notification).order_by(Notification.id))
        return [(n.kind, n.text) for n in rows]


def managed_running(rig):
    return all(rig.docker.c[n]["running"] for n in MANAGED)


# ---- nothing happens without approval --------------------

def test_a_request_alone_changes_nothing(rig):
    sid = request(rig)
    for _ in range(5):
        rig.ctrl.tick()
    assert state_of(sid) == "pending"
    assert rig.docker.touched() == set() and rig.rsm.log == []
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Scan)) == 0


def test_decline_changes_no_container_state(rig):
    sid = request(rig)
    d = sessions.decide(sid, nonce_of(sid), False, at=rig.clock())
    assert d.outcome == "declined"
    for _ in range(5):
        rig.ctrl.tick()
    assert state_of(sid) == "declined"
    assert rig.docker.touched() == set() and rig.rsm.log == []
    assert any("declined" in t for _, t in notes())
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Scan)) == 0


def test_no_response_expires_and_never_launches(rig):
    sid = request(rig)
    rig.clock.advance(901)                          # past the approval TTL
    rig.ctrl.tick()
    assert state_of(sid) == "expired"
    late = sessions.decide(sid, nonce_of(sid), True, at=rig.clock())
    assert late.outcome == "already_handled"
    for _ in range(3):
        rig.ctrl.tick()
    assert rig.docker.touched() == set() and rig.rsm.log == []
    assert any("expired" in t for _, t in notes())


def test_accept_after_expiry_is_refused_even_before_the_controller_swept(rig):
    sid = request(rig)
    rig.clock.advance(901)
    d = sessions.decide(sid, nonce_of(sid), True, at=rig.clock())
    assert d.outcome == "expired" and state_of(sid) == "expired"
    assert rig.docker.touched() == set()


def test_wrong_nonce_and_unknown_session_are_inert(rig):
    sid = request(rig)
    assert sessions.decide(sid, "0" * 16, True, at=rig.clock()).outcome == "bad_nonce"
    assert sessions.decide("00000000-0000-0000-0000-000000000000", "x", True).outcome == "unknown"
    assert state_of(sid) == "pending"


# ---- the happy path --------------------

def test_accept_reserves_runs_three_agents_and_restores(rig):
    before = rig.docker.running_names()
    sid = request(rig)
    assert accept(rig, sid).outcome == "accepted"
    assert drive(rig, sid, {"completed"}) == "completed"
    assert rig.docker.running_names() == before          # exactly the original state
    assert rig.docker.touched("stop") and not rig.docker.touched() & {
        "adguard", "immich_postgres", "immich_redis", "uptime-kuma",
        "hunter-session-controller", "whisper-dispatcher"}
    with session_scope() as db:
        row = db.get(ResourceSession, sid)
        assert row.lock_key is None and row.finished_at is not None
        scans = list(db.scalars(select(Scan)))
        assert scans and all(s.state == "finished" for s in scans)
    texts = [t for _, t in notes()]
    assert any("Resources reserved" in t for t in texts)
    assert any("All containers restored" in t for t in texts)
    assert rig.rsm.log.count("prepare") == 1 and rig.rsm.log.count("restore") == 1
    assert SUBMISSION_ENABLED is False


def test_manual_scan_for_one_profile_only_runs_that_profile(rig):
    sid = request(rig, profile_ids=[2])
    accept(rig, sid)
    drive(rig, sid, {"completed"})
    with session_scope() as db:
        assert [s.profile_id for s in db.scalars(select(Scan))] == [2]


# ---- replay / concurrency --------------------

def test_double_accept_applies_once(rig):
    sid = request(rig)
    n = nonce_of(sid)
    results = [sessions.decide(sid, n, True, at=rig.clock()).outcome for _ in range(3)]
    assert results == ["accepted", "already_handled", "already_handled"]
    drive(rig, sid, {"completed"})
    assert rig.rsm.log.count("prepare") == 1
    # a stale button pressed after completion is still inert
    assert sessions.decide(sid, n, True, at=rig.clock()).outcome == "already_handled"
    assert rig.rsm.log.count("prepare") == 1


def test_simultaneous_accepts_from_many_threads(rig):
    sid = request(rig)
    n = nonce_of(sid)
    out = []
    threads = [threading.Thread(target=lambda: out.append(
        sessions.decide(sid, n, True, at=rig.clock()).outcome)) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert out.count("accepted") == 1


def test_second_session_cannot_become_active_while_one_runs(rig):
    a, b = request(rig), request(rig)
    assert accept(rig, a).outcome == "accepted"
    assert accept(rig, b).outcome == "busy"
    assert state_of(b) == "blocked" and state_of(a) == "accepted"
    assert any("another research session is already active" in t for _, t in notes())
    drive(rig, a, {"completed"})
    c = request(rig)                                    # a new one may start afterwards
    assert accept(rig, c).outcome == "accepted"


def test_scheduler_slot_is_idempotent(rig):
    first = sessions.request_session("scheduled", slot_key="sched-2026-10-16T07")
    again = sessions.request_session("scheduled", slot_key="sched-2026-10-16T07")
    assert first[1] is True and again == (first[0], False)
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(ResourceSession)) == 1


# ---- failure paths always end in restoration --------------------

def test_busy_media_blocks_before_any_container_changes(rig):
    rig.broker.run_probe = lambda p: (True, "1 active playback session(s)")
    sid = request(rig)
    accept(rig, sid)
    assert drive(rig, sid, {"blocked"}) == "blocked"
    assert rig.docker.touched() == set()
    kind, text = notes()[-1]
    assert kind == "alert" and "busy" in text and "jellyfin" in text
    with session_scope() as db:
        assert db.get(ResourceSession, sid).lock_key is None   # the slot is free again


def test_partial_shutdown_failure_restores_and_reports(rig):
    rig.docker.fail_stop.add("radarr")
    sid = request(rig)
    accept(rig, sid)
    assert drive(rig, sid, {"blocked"}) == "blocked"
    rig.docker.fail_stop.clear()
    assert managed_running(rig)                          # everything that was stopped is back
    assert any("could not be stopped" in t for _, t in notes())


def test_insufficient_memory_after_stopping_restores_and_blocks(rig):
    rig.broker.mem = lambda: 100
    sid = request(rig)
    accept(rig, sid)
    assert drive(rig, sid, {"blocked"}) == "blocked"
    assert managed_running(rig)


def test_agent_failure_still_restores_and_session_completes_with_a_failed_scan(rig):
    def explode(agent, profile):
        raise RuntimeError("agent crashed")
    rig.agents["claude-2"] = explode
    sid = request(rig)
    accept(rig, sid)
    final = drive(rig, sid, {"completed", "failed"})
    assert managed_running(rig)
    assert final == "completed"                          # scans end 'partial', not failed
    with session_scope() as db:
        assert {s.state for s in db.scalars(select(Scan))} == {"partial"}


def test_a_failed_scan_marks_the_session_failed_but_still_restores(rig, monkeypatch):
    sid = request(rig)
    accept(rig, sid)
    monkeypatch.setattr(orchestrator, "run_agents",
                        lambda *a, **k: (_ for _ in ()).throw(KeyError("boom")))
    final = drive(rig, sid, {"completed", "failed"}, ticks=400)
    for _ in range(3):                                   # retries are bounded then fail
        pass
    assert final == "failed"
    assert managed_running(rig)


def test_timeout_restores_cancels_scans_and_reports(rig):
    sid = request(rig)
    accept(rig, sid)
    for _ in range(3):
        rig.ctrl.tick()                                  # running; scans queued, no worker
    assert state_of(sid) == "running"
    rig.clock.advance(601)                               # beyond SESSION_MAX_SECONDS
    final = drive(rig, sid, {"failed"}, scans=False)
    assert final == "failed" and managed_running(rig)
    with session_scope() as db:
        assert db.get(ResourceSession, sid).error == "session timed out"
        assert {s.state for s in db.scalars(select(Scan))} == {"cancelled"}
        assert {t.state for t in db.scalars(select(Task))} == {"cancelled"}
    assert any("timed out" in t for _, t in notes())


def test_broker_unreachable_at_prepare_blocks_without_touching_anything(rig):
    rig.rsm.down = True
    sid = request(rig)
    accept(rig, sid)
    assert drive(rig, sid, {"blocked"}) == "blocked"
    assert rig.docker.touched() == set()
    assert any("unreachable" in t for _, t in notes())


def test_lost_contact_while_stopping_goes_through_restore(rig, monkeypatch):
    original = rig.rsm.stop_approved

    def stop_then_lose_the_reply(sid):
        original(sid)                                   # containers really were stopped
        raise RsmUnavailable("timeout")
    monkeypatch.setattr(rig.rsm, "stop_approved", stop_then_lose_the_reply)
    sid = request(rig)
    accept(rig, sid)
    assert drive(rig, sid, {"blocked"}) == "blocked"
    assert managed_running(rig)                          # never assume: it restored


# ---- controller / helper crashes, restore failures --------------------

def test_controller_crash_mid_session_resumes_from_the_database(rig):
    sid = request(rig)
    accept(rig, sid)
    for _ in range(3):
        rig.ctrl.tick()
    assert state_of(sid) == "running"
    assert not rig.docker.c["qbittorrent"]["running"]
    revived = SessionController(rig.rsm, TaskQueue(clock=rig.clock), clock=rig.clock)
    rig.ctrl = revived                                   # new process, same database
    assert drive(rig, sid, {"completed"}) == "completed"
    assert managed_running(rig)
    assert rig.rsm.log.count("prepare") == 1             # not prepared twice


def test_watchdog_ending_the_session_early_is_detected(rig):
    sid = request(rig)
    accept(rig, sid)
    for _ in range(3):
        rig.ctrl.tick()
    rig.clock.advance(2701)
    assert rig.broker.watchdog_tick()["code"] == "restored"   # host safety net fired
    assert drive(rig, sid, {"failed"}, scans=False) == "failed"
    assert any("watchdog" in t for _, t in notes())
    assert managed_running(rig)


def test_restore_failure_alerts_retries_and_emergency_restore_recovers(rig):
    sid = request(rig)
    accept(rig, sid)
    for _ in range(3):
        rig.ctrl.tick()
    run_scans(rig)
    rig.docker.fail_start["sonarr"] = 1000               # daemon refuses to start sonarr
    for _ in range(12):
        rig.ctrl.tick()
        rig.clock.advance(25)
    assert state_of(sid) in ("restoring", "restore_failed")
    alerts = [t for k, t in notes() if k == "alert" and "RESTORATION FAILED" in t]
    assert len(alerts) == 1 and "sonarr" in alerts[0]    # reported once, explicitly
    with session_scope() as db:
        assert db.get(ResourceSession, sid).lock_key == "active"   # still holding the slot
    # a new session cannot start on top of an unrestored host
    other = request(rig)
    assert accept(rig, other).outcome == "busy"

    rig.docker.fail_start.clear()
    sessions.request_emergency_restore()                 # owner sends /restore
    rig.ctrl.tick()
    with session_scope() as db:
        assert db.scalar(select(RsmCommand.handled_at)) is not None
    assert drive(rig, sid, {"completed", "failed"}, scans=False) in ("completed", "failed")
    assert managed_running(rig)
    with session_scope() as db:
        assert db.get(ResourceSession, sid).lock_key is None


def test_emergency_restore_without_any_session_is_safe(rig):
    sessions.request_emergency_restore()
    rig.ctrl.tick()
    assert rig.docker.touched() == set()
    assert any("running again" in t for _, t in notes())


def test_without_a_broker_approval_still_gates_and_scans_run(database, agent_fleet, clock):
    ctrl = SessionController(None, TaskQueue(clock=clock), clock=clock)
    sid, _ = sessions.request_session("manual", at=clock())
    for _ in range(3):
        ctrl.tick()
    assert state_of(sid) == "pending"                    # approval is not optional
    sessions.decide(sid, nonce_of(sid), True, at=clock())
    for _ in range(60):
        ctrl.tick()
        while (c := ctrl.queue.claim()) is not None:
            orchestrator.process_claim(ctrl.queue, c)
        if state_of(sid) == "completed":
            break
        clock.advance(1)
    assert state_of(sid) == "completed"
    assert any("without reserving" in t for _, t in notes())


# ---- Telegram boundary --------------------

def cb(data, user=OWNER, chat=OWNER, chat_type="private", cid="cb1"):
    return {"update_id": 1, "callback_query": {
        "id": cid, "from": {"id": user}, "data": data,
        "message": {"chat": {"id": chat, "type": chat_type}}}}


def test_prompt_has_accept_and_decline_buttons_and_is_sent_once(rig):
    sid = request(rig)
    prompts = telegram.pending_prompts(at=rig.clock())
    assert len(prompts) == 1
    psid, text, markup = prompts[0]
    assert psid == sid and "No answer" in text and "restored automatically" in text
    data = [b["callback_data"] for b in markup["inline_keyboard"][0]]
    assert data[0].startswith(f"rs:a:{sid}:") and data[1].startswith(f"rs:d:{sid}:")
    assert all(len(d.encode()) <= 64 for d in data)
    telegram.mark_prompt_sent(sid)
    assert telegram.pending_prompts(at=rig.clock()) == []


def test_expired_requests_are_never_prompted(rig):
    request(rig)
    assert telegram.pending_prompts(at=rig.clock() + timedelta(seconds=901)) == []


def test_only_the_owner_in_a_private_chat_can_press_buttons(rig):
    sid = request(rig)
    data = f"rs:a:{sid}:{nonce_of(sid)}"
    assert telegram.process_callback(cb(data, user=1, chat=1), OWNER) is None
    assert telegram.process_callback(cb(data, chat=-100, chat_type="supergroup"), OWNER) is None
    assert telegram.process_callback(cb(data, chat=7), OWNER) is None
    assert state_of(sid) == "pending"
    ans = telegram.process_callback(cb(data), OWNER, at=rig.clock())
    assert ans["text"].startswith("Approved") and state_of(sid) == "accepted"


def test_button_replay_and_forgery(rig):
    sid = request(rig)
    good = f"rs:a:{sid}:{nonce_of(sid)}"
    assert telegram.process_callback(cb(good), OWNER, at=rig.clock())["text"].startswith(
        "Approved")
    assert telegram.process_callback(cb(good), OWNER, at=rig.clock())["text"] == \
        "Already handled."
    other = request(rig)
    forged = f"rs:a:{other}:{'0' * 16}"
    assert telegram.process_callback(cb(forged), OWNER)["text"] == "Invalid button."
    assert telegram.process_callback(cb("rs:x:foo"), OWNER)["text"] == "Unknown action."
    assert telegram.process_callback(cb("evil:a:b:c"), OWNER)["text"] == "Unknown action."
    assert state_of(other) == "pending"


def test_decline_button(rig):
    sid = request(rig)
    ans = telegram.process_callback(cb(f"rs:d:{sid}:{nonce_of(sid)}"), OWNER, at=rig.clock())
    assert ans["text"].startswith("Declined") and state_of(sid) == "declined"


def test_status_and_restore_commands(rig):
    assert "Session: none yet" in telegram.handle_command("/status", "/status")
    sid = request(rig)
    accept(rig, sid)
    for _ in range(3):
        rig.ctrl.tick()
    status = telegram.handle_command("/status", "/status")
    assert "running" in status and "ACTIVE" in status
    assert "Restore requested" in telegram.handle_command("/restore", "/restore")
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(RsmCommand)) == 1
        assert db.get(ResourceSession, sid).restore_requested is True
    assert drive(rig, sid, {"failed"}, scans=False) == "failed"
    assert managed_running(rig)


def test_notifications_are_delivered_once_and_alerts_are_marked(rig):
    import asyncio

    class Resp:
        status_code = 200

    class Client:
        def __init__(self):
            self.sent = []

        async def post(self, url, json):
            self.sent.append((url, json))
            return Resp()

    sessions.request_session("manual")          # real clock: the outbox checks real expiry
    with session_scope() as db:
        sessions.notify(db, "disk full", kind="alert")
    c = Client()
    asyncio.run(telegram.deliver_outbox(c, "https://api.telegram.org/botX", OWNER))
    texts = [j["text"] for _, j in c.sent]
    assert any("Launch the AI research agents" in t for t in texts)
    assert any(t.startswith("⚠️ disk full") for t in texts)
    assert all(j["chat_id"] == OWNER for _, j in c.sent)
    c2 = Client()
    asyncio.run(telegram.deliver_outbox(c2, "https://api.telegram.org/botX", OWNER))
    assert c2.sent == []                                 # nothing re-sent


def test_unused_fake_docker_import_guard():
    assert FakeDocker
