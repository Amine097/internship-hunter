"""Discovery worker (the only RQ consumer). Agent containers do not run workers."""
import os

from hunter import queueing
from hunter.orchestrator import sweep_stale_scans


def validate_identity(queue_name: str, agent_name: str | None) -> None:
    """The consumer is a trusted component: it must not carry an agent identity/credential."""
    if queue_name != queueing.SCAN_QUEUE:
        raise ValueError(f"Invalid queue {queue_name!r}")
    if agent_name:
        raise ValueError("The discovery worker must not carry an agent identity")


def main():
    queue_name = os.environ.get("HUNTER_QUEUE", queueing.SCAN_QUEUE)
    validate_identity(queue_name, os.environ.get("HUNTER_AGENT_NAME"))
    sweep_stale_scans()  # recover scans orphaned by a previous crash/OOM-kill
    queueing.make_worker().work()


if __name__ == "__main__":
    main()
