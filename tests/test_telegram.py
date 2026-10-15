import pytest

from hunter import telegram
from hunter.telegram import handle_command, process_update

OWNER = 4242


def update(text, user=OWNER, chat=OWNER, chat_type="private"):
    return {"update_id": 1, "message": {
        "from": {"id": user}, "chat": {"id": chat, "type": chat_type}, "text": text,
    }}


@pytest.fixture(autouse=True)
def _env(database, fake_redis):
    yield


def test_strangers_and_groups_are_ignored():
    assert process_update(update("/profiles", user=1, chat=1), OWNER) is None
    assert process_update(update("/profiles", chat=-100, chat_type="supergroup"), OWNER) is None
    assert process_update({"update_id": 2, "message": {"text": "/scan"}}, OWNER) is None
    assert process_update({"update_id": 3}, OWNER) is None


def test_plain_text_gets_no_reply():
    assert process_update(update("hello"), OWNER) is None


def test_profiles_lists_two_profiles():
    chat_id, text = process_update(update("/profiles"), OWNER)
    assert chat_id == OWNER
    assert text.count("\n") == 1 and "Summer 2027" in text and "Part-time" in text


def test_help_states_submission_disabled():
    assert "submission disabled" in handle_command("/help", "/help")


def test_scan_all_and_single():
    assert handle_command("/scan", "/scan").startswith("Queued scans: [")
    assert "queued or already running" in handle_command("/scan", "/scan 1")
    assert "Usage" in handle_command("/scan", "/scan abc")
    assert "unavailable" in handle_command("/scan", "/scan 999")


def test_bot_suffix_command():
    _, text = process_update(update("/scan@HunterBot 1"), OWNER)
    assert "queued or already running" in text


def test_status_agents_jobs_empty_states():
    assert "No scan yet" in handle_command("/status", "/status")
    assert "No agent run" in handle_command("/agents", "/agents")
    assert "No jobs yet" in handle_command("/jobs", "/jobs")
    assert "Unknown" in handle_command("/apply", "/apply")


def test_handler_failure_does_not_crash(monkeypatch):
    def boom(*a):
        raise RuntimeError("db gone")

    monkeypatch.setattr(telegram, "handle_command", boom)
    assert process_update(update("/profiles"), OWNER)[1] == "Command failed; check service logs."


def test_scan_reports_redis_outage(monkeypatch):

    def broken():
        raise ConnectionError("down")

    from hunter import queueing
    monkeypatch.setattr(queueing, "redis_connection", broken)
    assert "Redis unreachable" in handle_command("/scan", "/scan 1")
    assert "Could not queue" in handle_command("/scan", "/scan")
