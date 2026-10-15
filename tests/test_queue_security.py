"""Security regression tests for the Redis/RQ trust boundary.

Each attack is first shown to WORK against the original (pickle + name-based dispatch)
configuration, then shown to be BLOCKED by the hardened queue/worker.
"""
import base64
import pickle
from pathlib import Path

import pytest
from rq import Queue, SimpleWorker
from rq.job import Job
from rq.serializers import JSONSerializer
from rq.timeouts import TimerDeathPenalty

from hunter import queueing
from hunter.queueing import ForgedJobError, HardenedJob


class Pwn:
    """Pickle payload that writes a file when *loaded*."""
    def __init__(self, target):
        self.target = target

    def __reduce__(self):
        return (Path.write_text, (Path(self.target), "pwned"))


def plain_worker(connection, queue_name="discovery", serializer=None):
    kwargs = {"serializer": serializer} if serializer else {}
    worker = SimpleWorker([Queue(queue_name, connection=connection, **kwargs)],
                          connection=connection, **kwargs)
    worker.death_penalty_class = TimerDeathPenalty
    return worker


# 1 -- pickle deserialization -------------------------------------------------------------

def _enqueue_pickled_gadget(conn, sentinel):
    """What an attacker with Redis access can do: a pickled job calling Path.write_text."""
    job = Job.create(Path.write_text, args=(Path(sentinel), "pwned"), connection=conn)
    job.origin = "discovery"
    job.save()
    Queue("discovery", connection=conn).push_job_id(job.id)
    return job


def test_control_default_rq_unpickles_attacker_payload(fake_redis, tmp_path):
    """ORIGINAL VULNERABILITY: a job pickled by anyone with Redis access runs code."""
    sentinel = tmp_path / "pwned-by-worker"
    conn = fake_redis()
    _enqueue_pickled_gadget(conn, sentinel)
    plain_worker(conn).work(burst=True, with_scheduler=False)
    assert sentinel.read_text() == "pwned"


def test_pickled_job_is_not_deserialized_by_hardened_worker(drain, fake_redis, tmp_path):
    sentinel = tmp_path / "pwned-by-worker"
    conn = fake_redis()
    job = _enqueue_pickled_gadget(conn, sentinel)  # identical payload to the control above
    drain(conn)  # hardened worker; must not execute and must not crash
    assert not sentinel.exists()
    assert conn.llen("rq:queue:discovery") == 0  # it was consumed (and dropped), not skipped
    assert Job.fetch(job.id, connection=conn).get_status(refresh=True) != "finished"


def test_json_serializer_never_calls_pickle(drain, fake_redis, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("pickle.loads was called")

    monkeypatch.setattr(pickle, "loads", boom)
    conn = fake_redis()
    job_id = queueing.make_queue(connection=conn).enqueue(queueing.SCAN_FUNC, 12345).id
    fetched = Job.fetch(job_id, connection=conn, serializer=JSONSerializer)
    assert list(fetched.args) == [12345]
    # the raw job data in Redis is JSON text, not a pickle stream
    raw = conn.hget(f"rq:job:{job_id}", "data")
    assert not raw.startswith(b"\x80")


# 2 -- function-name injection ---------------------------------------------------------------

def test_control_name_based_dispatch_runs_any_callable(drain, fake_redis, tmp_path):
    """ORIGINAL VULNERABILITY: even with JSON, a job may name any importable callable."""
    sentinel = tmp_path / "pwned-by-name"
    conn = fake_redis()
    Queue("discovery", connection=conn, serializer=JSONSerializer).enqueue(
        "subprocess.run", ["touch", str(sentinel)])
    plain_worker(conn, serializer=JSONSerializer).work(burst=True, with_scheduler=False)
    assert sentinel.exists()


@pytest.mark.parametrize("func_name,args", [
    ("subprocess.run", [["touch", "{s}"]]),
    ("os.system", ["touch {s}"]),
    ("hunter.agents.run_plan", ["codex", {}]),
    ("hunter.orchestrator._run_scan", [1]),          # real module, not the allowlisted entry
    ("hunter.queueing.make_worker", []),
])
def test_forged_function_names_rejected(drain, fake_redis, tmp_path, func_name, args):
    sentinel = tmp_path / "pwned"
    args = [a.format(s=sentinel) if isinstance(a, str) else
            [x.format(s=sentinel) for x in a] if isinstance(a, list) and a
            and isinstance(a[0], str) else a for a in args]
    conn = fake_redis()
    q = Queue("discovery", connection=conn, serializer=JSONSerializer)
    job = q.enqueue(func_name, *args)
    drain(conn)
    assert not sentinel.exists()
    failed = Job.fetch(job.id, connection=conn, serializer=JSONSerializer, )
    assert failed.get_status(refresh=True) == "failed"
    assert "ForgedJobError" in (failed.latest_result().exc_string or "")


@pytest.mark.parametrize("args,kwargs", [
    (("1",), {}), ((True,), {}), ((0,), {}), ((-5,), {}), ((1, 2), {}),
    ((), {}), ((1,), {"x": 1}), (({"a": 1},), {}),
])
def test_scan_job_argument_shape_enforced(drain, fake_redis, args, kwargs):
    conn = fake_redis()
    job = Queue("discovery", connection=conn, serializer=JSONSerializer).enqueue(
        queueing.SCAN_FUNC, *args, **kwargs)
    drain(conn)
    assert Job.fetch(job.id, connection=conn, serializer=JSONSerializer).get_status(
        refresh=True) == "failed"


def test_callbacks_are_rejected(drain, fake_redis, tmp_path):
    sentinel = tmp_path / "cb"
    conn = fake_redis()
    q = Queue("discovery", connection=conn, serializer=JSONSerializer)
    job = q.enqueue(queueing.SCAN_FUNC, 1, on_success="os.system")
    drain(conn)
    assert not sentinel.exists()
    assert Job.fetch(job.id, connection=conn, serializer=JSONSerializer).get_status(
        refresh=True) == "failed"


def test_validate_unit():
    job = HardenedJob.__new__(HardenedJob)
    job._func_name, job._args, job._kwargs, job._instance = "os.system", ("x",), {}, None
    job._success_callback_name = job._failure_callback_name = None
    job._stopped_callback_name = None
    with pytest.raises(ForgedJobError):
        job._validate()


# 3 -- result poisoning ---------------------------------------------------------------------

def _poison_latest_result(conn, job_id, payload: bytes):
    key = f"rq:results:{job_id}"
    entries = conn.xrevrange(key, count=1)
    assert entries, "job produced no result entry"
    _, fields = entries[0]
    fields = dict(fields)
    fields[b"return_value"] = base64.b64encode(payload)
    conn.delete(key)
    conn.xadd(key, fields)


def _finished_job(conn, job_class, serializer=None):
    kwargs = {"serializer": serializer} if serializer else {}
    q = Queue("discovery", connection=conn, job_class=job_class, **kwargs)
    job = q.enqueue("builtins.len", [1, 2, 3])  # harmless callable for the control
    return q, job


def test_control_default_rq_unpickles_poisoned_result(drain, fake_redis, tmp_path):
    """ORIGINAL VULNERABILITY: orchestrator calling return_value() unpickles agent data."""
    sentinel = tmp_path / "pwned-by-result"
    conn = fake_redis()
    _, job = _finished_job(conn, Job)
    plain_worker(conn).work(burst=True, with_scheduler=False)
    _poison_latest_result(conn, job.id, pickle.dumps(Pwn(sentinel)))
    Job.fetch(job.id, connection=conn).return_value()
    assert sentinel.read_text() == "pwned"


def test_poisoned_result_is_inert_with_json_serializer(drain, fake_redis, tmp_path):
    sentinel = tmp_path / "pwned-by-result"
    conn = fake_redis()
    job_id = queueing.make_queue(connection=conn).enqueue(
        queueing.SCAN_FUNC, 999_999).id  # fails inside the job; result entry still written
    drain(conn)
    entries = conn.xrevrange(f"rq:results:{job_id}", count=1)
    assert entries
    _poison_latest_result(conn, job_id, pickle.dumps(Pwn(sentinel)))
    fetched = Job.fetch(job_id, connection=conn, serializer=JSONSerializer)
    try:
        fetched.return_value()
    except Exception:
        pass  # failing to parse hostile data is the correct outcome
    assert not sentinel.exists()
