"""Private Telegram long-polling bot. Strictly restricted to the owner user ID."""
import asyncio
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select, update

from hunter import sessions
from hunter.db import session_scope
from hunter.models import (
    SESSION_ACTIVE,
    AgentRun,
    Job,
    Notification,
    ResourceSession,
    Scan,
    SearchProfile,
)
from hunter.settings import get_settings

CALLBACK_PREFIX = "rs"   # callback_data: rs:<a|d>:<session_id>:<nonce>  (<= 64 bytes)


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


def process_callback(update: dict, owner: int, at: datetime | None = None) -> dict | None:
    """Owner-only inline-button handler. Returns {"id", "text"} for answerCallbackQuery.

    Authentication: sender id AND chat id must be the owner and the chat private. The
    session nonce binds the button to one request; the state transition is single-use and
    expiry-checked in ``sessions.decide`` (replays and double taps are answered, not applied).
    """
    cq = update.get("callback_query")
    if not cq:
        return None
    msg = cq.get("message") or {}
    chat = msg.get("chat") or {}
    if (cq.get("from") or {}).get("id") != owner:
        return None
    if chat.get("type") != "private" or chat.get("id") != owner:
        return None
    parts = (cq.get("data") or "").split(":")
    if len(parts) != 4 or parts[0] != CALLBACK_PREFIX or parts[1] not in ("a", "d"):
        return {"id": cq.get("id"), "text": "Unknown action."}
    d = sessions.decide(parts[2], parts[3], accept=parts[1] == "a", at=at)
    answers = {
        "accepted": "Approved. Reserving resources...",
        "declined": "Declined. Nothing was changed.",
        "expired": "This request has expired.",
        "already_handled": "Already handled.",
        "busy": "Another session is already active.",
        "unknown": "Unknown request.",
        "bad_nonce": "Invalid button.",
    }
    return {"id": cq.get("id"), "text": answers.get(d.outcome, d.outcome)}


def pending_prompts(at: datetime | None = None) -> list[tuple[str, str, dict]]:
    at = at or datetime.now(timezone.utc)
    out = []
    with session_scope() as db:
        rows = db.scalars(select(ResourceSession).where(
            ResourceSession.state == "pending", ResourceSession.prompt_sent_at.is_(None),
            ResourceSession.expires_at > at))
        for r in rows:
            until = r.expires_at.astimezone(timezone.utc).strftime("%H:%M UTC")
            what = {"scheduled": "Scheduled", "manual": "Manual", "api": "API"}[r.trigger]
            scope = "all enabled profiles" if r.profile_ids is None else f"profiles {r.profile_ids}"
            text = (f"{what} research session ({scope}).\n"
                    "Launch the AI research agents now? Approving temporarily stops "
                    "administrator-approved non-essential containers to free memory; they "
                    "are restored automatically afterwards.\n"
                    f"No answer by {until} = no launch.")
            markup = {"inline_keyboard": [[
                {"text": "Accept", "callback_data": f"{CALLBACK_PREFIX}:a:{r.id}:{r.nonce}"},
                {"text": "Decline", "callback_data": f"{CALLBACK_PREFIX}:d:{r.id}:{r.nonce}"},
            ]]}
            out.append((r.id, text, markup))
    return out


def mark_prompt_sent(session_id: str, at: datetime | None = None) -> None:
    with session_scope() as db:
        db.execute(update(ResourceSession).where(
            ResourceSession.id == session_id, ResourceSession.prompt_sent_at.is_(None),
        ).values(prompt_sent_at=at or datetime.now(timezone.utc)))


def pending_notifications() -> list[tuple[int, str, str]]:
    with session_scope() as db:
        return [(n.id, n.text, n.kind) for n in db.scalars(
            select(Notification).where(Notification.sent_at.is_(None)).order_by(Notification.id)
            .limit(20))]


def mark_notification_sent(notification_id: int) -> None:
    with session_scope() as db:
        db.execute(update(Notification).where(
            Notification.id == notification_id, Notification.sent_at.is_(None),
        ).values(sent_at=datetime.now(timezone.utc)))


async def deliver_outbox(client, base: str, owner: int) -> None:
    """Sends prompts and notifications. At-least-once: marked sent only after Telegram acks."""
    for sid, text, markup in pending_prompts():
        r = await client.post(f"{base}/sendMessage", json={
            "chat_id": owner, "text": text, "reply_markup": markup})
        if r.status_code == 200:
            mark_prompt_sent(sid)
    for nid, text, kind in pending_notifications():
        prefix = "\u26a0\ufe0f " if kind == "alert" else ""
        r = await client.post(f"{base}/sendMessage", json={
            "chat_id": owner, "text": (prefix + text)[:4000]})
        if r.status_code == 200:
            mark_notification_sent(nid)


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
        async def outbox_loop():
            while True:
                try:
                    await deliver_outbox(client, base, owner)
                except Exception as exc:  # never let delivery problems stop polling
                    print(f"Telegram outbox error: {type(exc).__name__}", flush=True)
                await asyncio.sleep(2)

        outbox = asyncio.create_task(outbox_loop())  # noqa: F841 - kept alive for the process
        offset = None
        while True:
            try:
                resp = await client.get(f"{base}/getUpdates", params={
                    "offset": offset, "timeout": 20,
                    "allowed_updates": '["message", "callback_query"]',
                })
                resp.raise_for_status()
                for update in resp.json().get("result", []):
                    offset = update["update_id"] + 1
                    cb = process_callback(update, owner)
                    if cb is not None:
                        await client.post(f"{base}/answerCallbackQuery", json={
                            "callback_query_id": cb["id"], "text": cb["text"]})
                        continue
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
            "/scan [profile_id] - ask to start a research session (needs your approval)\n"
            "/status - current session and recent scans\n"
            "/restore - force-restore stopped containers\n"
            "/profiles /scans /agents /jobs"
        )
    if command == "/profiles":
        with session_scope() as db:
            rows = db.query(SearchProfile).order_by(SearchProfile.id).all()
            return "\n".join(
                f"{p.id}: {p.name} ({'on' if p.enabled else 'off'})" for p in rows
            ) or "No profiles."
    if command == "/scans":
        with session_scope() as db:
            scans = db.query(Scan).order_by(Scan.id.desc()).limit(5).all()
            return "Latest scans:\n" + "\n".join(
                f"#{s.id} {s.state} — {s.discovered} jobs" for s in scans
            ) if scans else "No scan yet. Use /scan"
    if command == "/status":
        with session_scope() as db:
            sess = db.scalar(select(ResourceSession).order_by(
                ResourceSession.created_at.desc()).limit(1))
            lines = []
            if sess is None:
                lines.append("Session: none yet.")
            else:
                active = sess.state in SESSION_ACTIVE
                lines.append(f"Session {sess.id[:8]}: {sess.state}"
                             + (" (ACTIVE)" if active else ""))
                if sess.error:
                    lines.append(f"  reason: {sess.error}")
                broker = sess.broker or {}
                if broker.get("seconds_remaining") is not None:
                    lines.append(f"  broker: {broker.get('phase')}, "
                                 f"{broker['seconds_remaining']}s left, "
                                 f"stopped {len(broker.get('stopped') or [])}")
            scans = db.query(Scan).order_by(Scan.id.desc()).limit(3).all()
            lines += [f"Scan #{s.id}: {s.state} ({s.discovered} jobs)" for s in scans]
            return "\n".join(lines)
    if command == "/restore":
        sessions.request_emergency_restore()
        return ("Restore requested. The session controller will restore every container "
                "that was stopped for a session and report the result.")
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
        profile_ids = None
        if len(arguments) > 1:
            if not arguments[1].isdigit():
                return "Usage: /scan or /scan <profile_id>"
            profile_ids = [int(arguments[1])]
            with session_scope() as db:
                profile = db.get(SearchProfile, profile_ids[0])
                if profile is None or not profile.enabled:
                    return "Profile unavailable. Use /profiles"
        sid, _ = sessions.request_session("manual", profile_ids)
        return ("Approval requested - nothing has started. Use the Accept / Decline buttons "
                f"in the prompt that follows (request {sid[:8]}).")
    return "Unknown command. Use /help"


if __name__ == "__main__":
    asyncio.run(main())
