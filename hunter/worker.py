import os

from redis import Redis
from rq import Queue, Worker

from hunter.settings import get_settings


def main():
    queue_name = os.environ.get("HUNTER_QUEUE", "discovery")
    allowed = {"discovery", "claude-1", "claude-2", "codex"}
    if queue_name not in allowed:
        raise ValueError(f"Invalid queue {queue_name}")
    connection = Redis.from_url(get_settings().redis_url)
    worker = Worker([Queue(queue_name, connection=connection)], connection=connection)
    worker.work()


if __name__ == "__main__":
    main()
