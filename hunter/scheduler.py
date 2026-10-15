from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from hunter.orchestrator import enqueue_all_profiles
from hunter.settings import get_settings


def scheduled_scan() -> None:
    queued, errors = enqueue_all_profiles()
    print(f"scheduled scans queued={queued} errors={errors}", flush=True)


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
