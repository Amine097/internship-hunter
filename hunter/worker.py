import os

from redis import Redis
from rq import Queue, Worker

from hunter.settings import get_settings

QUEUES = {"discovery", "claude-1", "claude-2", "codex"}


def validate_identity(queue_name: str, agent_name: str | None) -> None:
    """Credential isolation: a worker only ever serves the queue of its own identity."""
    if queue_name not in QUEUES:
        raise ValueError(f"Invalid queue {queue_name}")
    if queue_name == "discovery":
        if agent_name:
            raise ValueError("The discovery worker must not carry an agent identity")
    elif agent_name != queue_name:
        raise ValueError(f"Worker identity {agent_name!r} cannot serve queue {queue_name!r}")


def main():
    queue_name = os.environ.get("HUNTER_QUEUE", "discovery")
    validate_identity(queue_name, os.environ.get("HUNTER_AGENT_NAME"))
    connection = Redis.from_url(get_settings().redis_url)
    Worker([Queue(queue_name, connection=connection)], connection=connection).work()


if __name__ == "__main__":
    main()
