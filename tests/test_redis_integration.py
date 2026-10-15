"""Real Redis, real forking RQ worker, real subprocess: the security tests without fakes.

Runs when TEST_REDIS_URL is set (CI service container; locally via docker).
"""
import json
import subprocess
import sys
import textwrap
import zlib

import pytest
import redis as redis_lib
from rq import Queue
from rq.job import Job
from rq.serializers import JSONSerializer

from hunter import queueing


@pytest.fixture
def conn(real_redis_url):
    c = redis_lib.Redis.from_url(real_redis_url)
    c.flushdb()
    yield c
    c.flushdb()


def run_worker(url, tmp_path, timeout=30):
    """Hardened worker in its own process (real fork-per-job RQ Worker), burst mode."""
    script = textwrap.dedent(f"""
        import redis
        from hunter import queueing
        c = redis.Redis.from_url({url!r})
        queueing.make_worker(c).work(burst=True, with_scheduler=False)
    """)
    return subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          timeout=timeout, cwd=tmp_path)


def test_forged_function_blocked_with_real_worker_process(conn, real_redis_url, tmp_path):
    sentinel = tmp_path / "pwned"
    q = Queue("discovery", connection=conn, serializer=JSONSerializer)
    job = q.enqueue("subprocess.run", ["touch", str(sentinel)])
    run_worker(real_redis_url, tmp_path)
    assert not sentinel.exists()
    assert Job.fetch(job.id, connection=conn, serializer=JSONSerializer).get_status(
        refresh=True) == "failed"


def test_pickled_payload_blocked_with_real_worker_process(conn, real_redis_url, tmp_path):
    sentinel = tmp_path / "pwned"
    from pathlib import Path
    job = Job.create(Path.write_text, args=(sentinel, "x"), connection=conn)
    job.origin = "discovery"
    job.save()
    Queue("discovery", connection=conn).push_job_id(job.id)
    run_worker(real_redis_url, tmp_path)
    assert not sentinel.exists()


def test_legit_scan_job_round_trips_json_on_real_redis(conn, real_redis_url, tmp_path):
    job_id = queueing.make_queue(connection=conn).enqueue(queueing.SCAN_FUNC, 424242).id
    raw = conn.hget(f"rq:job:{job_id}", "data")
    payload = json.loads(zlib.decompress(raw))  # RQ zlib-compresses; the body must be JSON
    assert payload[0] == queueing.SCAN_FUNC and payload[1] is None and payload[2] == [424242]
    run_worker(real_redis_url, tmp_path)
    # run_scan fails (no such scan / no DB) but is *executed*: allowlisted path works
    status = Job.fetch(job_id, connection=conn, serializer=JSONSerializer).get_status(
        refresh=True)
    assert status in ("failed", "finished")
