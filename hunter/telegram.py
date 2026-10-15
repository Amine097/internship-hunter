"""Private Telegram long-polling bot. Strictly restricted to the owner user ID."""
import asyncio

import httpx

from hunter.db import session_scope
from hunter.models import Scan, SearchProfile
from hunter.orchestrator import enqueue_all_profiles, enqueue_scan
from hunter.settings import get_settings


async def main():
    settings = get_settings()
    token = settings.telegram_bot_token
    owner = (int(settings.telegram_allowed_user_id)
             if settings.telegram_allowed_user_id.isdigit() else None)
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
                    msg = update.get("message", {})
                    if msg.get("from", {}).get("id") != owner:
                        continue
                    chat_id = msg.get("chat", {}).get("id")
                    if chat_id != owner:  # Private chats only.
                        continue
                    command = msg.get("text", "").split(" ")[0].split("@")[0].lower()
                    text = handle_command(command, msg.get("text", ""))
                    if text:
                        sent = await client.post(f"{base}/sendMessage", json={
                            "chat_id": chat_id, "text": text[:4000],
                        })
                        sent.raise_for_status()
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                print(f"Telegram polling error: {type(exc).__name__}", flush=True)
                await asyncio.sleep(5)


def handle_command(command: str, raw: str) -> str:
    if command in ("/start", "/help"):
        return "Internship Hunter V1 (read-only). Commands: /profiles /scan [id] /status"
    if command == "/profiles":
        with session_scope() as db:
            return "\n".join(
                f"{p.id}: {p.name} ({'on' if p.enabled else 'off'})"
                for p in db.query(SearchProfile).order_by(SearchProfile.id)
            )
    if command == "/status":
        with session_scope() as db:
            scans = db.query(Scan).order_by(Scan.id.desc()).limit(5).all()
            return "Latest scans:\n" + "\n".join(
                f"#{s.id} {s.state} — {s.discovered} jobs" for s in scans
            ) if scans else "No scan yet. Use /scan"
    if command == "/scan":
        arguments = raw.strip().split()
        if len(arguments) > 1:
            if not arguments[1].isdigit():
                return "Usage: /scan or /scan <profile_id>"
            try:
                return f"Scan queued: #{enqueue_scan(int(arguments[1]))}"
            except ValueError:
                return "Profile unavailable. Use /profiles"
        return f"Queued scans: {enqueue_all_profiles()}"
    return "Unknown command. Use /help"


if __name__ == "__main__":
    asyncio.run(main())
