import pytest

from hunter import queueing, worker


def test_validate_identity_rules():
    worker.validate_identity("discovery", None)
    for queue, name in [("claude-1", "claude-1"), ("codex", None), ("discovery", "codex"),
                        ("bogus", None), ("", None)]:
        with pytest.raises(ValueError):
            worker.validate_identity(queue, name)


def test_main_enforces_identity_before_touching_redis(monkeypatch):
    called = []
    monkeypatch.setattr(queueing, "make_worker", lambda *a, **k: called.append("worker"))
    monkeypatch.setenv("HUNTER_QUEUE", "discovery")
    monkeypatch.setenv("HUNTER_AGENT_NAME", "codex")
    with pytest.raises(ValueError):
        worker.main()
    assert called == []


def test_main_sweeps_stale_scans_then_works(monkeypatch):
    order = []

    class W:
        def work(self):
            order.append("work")

    monkeypatch.delenv("HUNTER_AGENT_NAME", raising=False)
    monkeypatch.setenv("HUNTER_QUEUE", "discovery")
    monkeypatch.setattr(worker, "sweep_stale_scans", lambda: order.append("sweep"))
    monkeypatch.setattr(queueing, "make_worker", lambda *a, **k: W())
    worker.main()
    assert order == ["sweep", "work"]
