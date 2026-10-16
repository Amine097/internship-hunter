import threading

import pytest

from hunter import worker
from hunter.taskqueue import TaskQueue


def test_worker_refuses_agent_identity(monkeypatch):
    monkeypatch.setenv("HUNTER_AGENT_NAME", "codex")
    with pytest.raises(ValueError):
        worker.main()
    worker.validate_identity(None)


def test_run_forever_processes_then_stops(database, run_tasks):
    from hunter import orchestrator
    orchestrator.enqueue_scan(1)
    seen, stop = [], threading.Event()

    def handler(queue, claim, **kw):
        seen.append(claim.scan_id)
        stop.set()

    assert worker.run_forever(TaskQueue(), stop, handler, poll=0.01) == 1
    assert seen == [1]


def test_run_forever_reaps_before_claiming(database, monkeypatch):
    calls = []

    class Q:
        def reap(self):
            calls.append("reap")
            return {}

        def claim(self):
            calls.append("claim")
            stop.set()

    stop = threading.Event()
    worker.run_forever(Q(), stop, lambda *a: None, poll=0.01)
    assert calls[:2] == ["reap", "claim"]
