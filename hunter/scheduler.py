from datetime import datetime
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from hunter import sessions
from hunter.settings import get_settings


def scheduled_scan() -> None:
    """07:00 / 13:00 / 20:00: ask the owner. Nothing runs, and no container changes, unless
    the owner accepts; an unanswered prompt expires."""
    settings = get_settings()
    slot = datetime.now(ZoneInfo(settings.tz)).strftime("%Y-%m-%dT%H")
    sid, created = sessions.request_session("scheduled", slot_key=f"sched-{slot}")
    print(f"scheduled approval request {sid[:8]} slot={slot} created={created}", flush=True)


def main():
    settings = get_settings()
    scheduler = BlockingScheduler(timezone=ZoneInfo(settings.tz))
    scheduler.add_job(
        scheduled_scan,
        CronTrigger.from_crontab(settings.scan_cron, timezone=ZoneInfo(settings.tz)),
        id="scheduled_scans", coalesce=True, max_instances=1,
        misfire_grace_time=1800,
    )
    scheduler.start()


if __name__ == "__main__":
    main()
