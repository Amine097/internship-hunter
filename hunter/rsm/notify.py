"""Optional direct Telegram message from the HOST, independent of the application, so a
watchdog restoration (or its failure) is reported even if the app/bot is down."""
import json
import urllib.request
from pathlib import Path

from hunter.rsm.policy import Notify


def send(notify: Notify | None, text: str, opener=urllib.request.urlopen) -> bool:
    if notify is None:
        return False
    try:
        token = Path(notify.bot_token_file).read_text().strip()
        body = json.dumps({"chat_id": notify.chat_id, "text": text[:3500]}).encode()
        req = urllib.request.Request(f"{notify.api_base}/bot{token}/sendMessage", data=body,
                                     headers={"Content-Type": "application/json"})
        with opener(req, timeout=10) as resp:  # noqa: S310 - https base from admin policy
            return 200 <= resp.status < 300
    except Exception:
        return False
