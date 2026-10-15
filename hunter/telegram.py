"""Private Telegram long-polling bot. Strictly restricted to the owner user ID."""
import asyncio
import logging

import httpx

from hunter.db import session_scope
from hunter.models import AgentRun, Job, Scan, SearchProfile
from hunter.orchestrator import enqueue_all_profiles, enqueue_scan
from hunter.settings import get_settings


def owner_id(raw: str) -> int | None:
    return int(raw) if raw.isdigit() else None


def process_update(update: dict, owner: int) -> tuple[int, str] | None:
    """Pure update -> reply mapping. Only the owner, in a private chat, gets any answer."""
    msg = update.get("message") or {}
    chat = msg.get("chat") or {}
    if (msg.get("from") or {}).get("id") != owner:
        return None
    if chat.get("type") != "private" or chat.get("id") != owner:
        return None
    raw = msg.get("text") or ""
    if not raw.startswith("/"):
        return None
    command = raw.split()[0].split("@")[0].lower()
    try:
        text = handle_command(command, raw)
    except Exception as exc:  # a failing handler must not kill the polling loop
        print(f"Command {command} failed: {type(exc).__name__}", flush=True)
        text = "Command failed; check service logs."
    return chat["id"], text


async def main():
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs contain the bot token
    settings = get_settings()
    token = settings.telegram_bot_token
    owner = owner_id(settings.telegram_allowed_user_id)
    if not token or owner is None:
        print("Telegram not configured; bot waiting for configuration/restart.", flush=True)
        while True:
            await asyncio.sleep(3600)
    base = f"https://api.telegram.org/bot{token}"
    async with httpx.AsyncClient(timeout=35) as client:
        offset = None
        while True:
            try:
                resp = await client.get(f"{base}/getUpdates", params={
                    "offset": offset, "timeout": 25, "allowed_updates": '["message"]',
                })
                resp.raise_for_status()
                for update in resp.json().get("result", []):
                    offset = update["update_id"] + 1
                    reply = process_update(update, owner)
                    if reply:
                        sent = await client.post(f"{base}/sendMessage", json={
                            "chat_id": reply[0], "text": reply[1][:4000],
                        })
                        sent.raise_for_status()
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                print(f"Telegram polling error: {type(exc).__name__}", flush=True)
                await asyncio.sleep(5)


def handle_command(command: str, raw: str) -> str:
    if command in ("/start", "/help"):
        return (
            "Internship Hunter V1 (read-only, submission disabled).\n"
            "/profiles /scan [id] /status /scans /agents /jobs"
        )
    if command == "/profiles":
        with session_scope() as db:
            rows = db.query(SearchProfile).order_by(SearchProfile.id).all()
            return "\n".join(
                f"{p.id}: {p.name} ({'on' if p.enabled else 'off'})" for p in rows
            ) or "No profiles."
    if command in ("/status", "/scans"):
        with session_scope() as db:
            scans = db.query(Scan).order_by(Scan.id.desc()).limit(5).all()
            return "Latest scans:\n" + "\n".join(
                f"#{s.id} {s.state} — {s.discovered} jobs" for s in scans
            ) if scans else "No scan yet. Use /scan"
    if command == "/agents":
        with session_scope() as db:
            runs = db.query(AgentRun).order_by(AgentRun.id.desc()).limit(6).all()
            return "Latest agent runs:\n" + "\n".join(
                f"scan #{r.scan_id} {r.agent}: {r.state} "
                f"({r.output.get('mode', '-')}, {len(r.output.get('queries', []))} queries)"
                for r in runs
            ) if runs else "No agent run yet."
    if command == "/jobs":
        with session_scope() as db:
            jobs = db.query(Job).order_by(Job.id.desc()).limit(10).all()
            return "Latest jobs:\n" + "\n".join(
                f"{j.title} — {j.company} ({j.location or 'location unknown'})" for j in jobs
            ) if jobs else "No jobs yet (no ATS source configured or none scanned)."
    if command == "/scan":
        arguments = raw.strip().split()
        try:
            if len(arguments) > 1:
                if not arguments[1].isdigit():
                    return "Usage: /scan or /scan <profile_id>"
                return f"Scan #{enqueue_scan(int(arguments[1]))} queued or already running"
            queued, errors = enqueue_all_profiles()
            if errors and not queued:
                return "Could not queue scans (no enabled profile or database error)."
            note = f" ({len(errors)} failed)" if errors else ""
            return f"Queued scans: {queued}{note}"
        except ValueError:
            return "Profile unavailable. Use /profiles"
    return "Unknown command. Use /help"


if __name__ == "__main__":
    asyncio.run(main())
