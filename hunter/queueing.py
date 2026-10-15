"""The only way jobs enter or leave Redis.

* JSON serialization everywhere: nothing read from Redis is ever unpickled.
* Jobs are checked on the *consumer* side against an allowlist (function, argument shape, no
  callbacks, no instance), so a forged entry in Redis cannot name an arbitrary callable.
* Only trusted components (api, telegram, scheduler, discovery) hold Redis credentials; the
  agent containers have none (see hunter/agent_runner.py).
"""
from functools import lru_cache

from redis import Redis
from rq import Queue, Worker
from rq.job import Job
from rq.serializers import JSONSerializer

from hunter.settings import get_settings

SCAN_FUNC = "hunter.orchestrator.run_scan"
SCAN_QUEUE = "discovery"


class ForgedJobError(Exception):
    """Raised for any queued job that is not exactly an allowlisted, well-formed scan."""


class HardenedJob(Job):
    def _validate(self) -> None:
        if self.func_name != SCAN_FUNC:
            raise ForgedJobError(f"function not allowlisted: {self.func_name!r}")
        args, kwargs = self.args, self.kwargs
        if (
            len(args) != 1 or kwargs or isinstance(args[0], bool) or not isinstance(args[0], int)
            or args[0] <= 0
        ):
            raise ForgedJobError("bad arguments")
        if self._success_callback_name or self._failure_callback_name \
                or self._stopped_callback_name:
            raise ForgedJobError("callbacks are not allowed")
        if self.instance is not None:
            raise ForgedJobError("bound-method jobs are not allowed")

    @property
    def func(self):
        self._validate()
        return super().func

    def perform(self):
        self._validate()
        return super().perform()


@lru_cache
def _redis(url: str) -> Redis:
    return Redis.from_url(url)


def redis_connection() -> Redis:
    return _redis(get_settings().redis_url)


def make_queue(name: str = SCAN_QUEUE, connection: Redis | None = None) -> Queue:
    return Queue(
        name, connection=connection or redis_connection(),
        serializer=JSONSerializer, job_class=HardenedJob,
    )


def make_worker(connection: Redis | None = None, worker_class=Worker) -> Worker:
    connection = connection or redis_connection()
    return worker_class(
        [make_queue(SCAN_QUEUE, connection)], connection=connection,
        serializer=JSONSerializer, job_class=HardenedJob,
    )


def enqueue_scan_job(scan_id: int) -> str:
    job = make_queue().enqueue(
        SCAN_FUNC, scan_id, job_timeout=600, result_ttl=3600, failure_ttl=86400,
    )
    return job.id
