"""Scan worker: claims tasks from PostgreSQL. Any number of workers may run concurrently."""
import logging
import os
import signal
import threading
import time

from hunter import orchestrator
from hunter.taskqueue import TaskQueue

log = logging.getLogger("hunter.worker")
POLL_SECONDS = 2.0
REAP_EVERY_SECONDS = 30.0


def validate_identity(agent_name: str | None) -> None:
    """The worker is a trusted component: it must not carry an agent identity/credential."""
    if agent_name:
        raise ValueError("The discovery worker must not carry an agent identity")


def run_forever(queue: TaskQueue | None = None, stop: threading.Event | None = None,
                handler=None, poll: float = POLL_SECONDS) -> int:
    """Main loop. Returns the number of tasks processed (used by tests with ``stop``)."""
    queue = queue or TaskQueue()
    stop = stop or threading.Event()
    handler = handler or orchestrator.process_claim
    processed, last_reap = 0, 0.0
    while not stop.is_set():
        if time.monotonic() - last_reap >= REAP_EVERY_SECONDS:
            result = queue.reap()
            if any(result.values()):
                log.warning("reaped abandoned tasks: %s", result)
            last_reap = time.monotonic()
        claim = queue.claim()
        if claim is None:
            stop.wait(poll)
            continue
        handler(queue, claim, stop=stop)
        processed += 1
    return processed


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    validate_identity(os.environ.get("HUNTER_AGENT_NAME"))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())  # finish the current task, then exit
    run_forever(stop=stop)


if __name__ == "__main__":
    main()
