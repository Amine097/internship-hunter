import pytest
from fastapi.testclient import TestClient

from hunter import api

H = {"X-Admin-Token": "t" * 40}


@pytest.fixture
def client(database):
    return TestClient(api.app)


def test_health_reports_submission_disabled(client):
    body = client.get("/health").json()
    assert body["submission_enabled"] is False
    assert body["mode"] == "demo"


def test_protected_routes_require_token(client):
    for path in ("/status", "/profiles", "/jobs", "/scans", "/agents"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert client.post("/scan/1").status_code == 401


def test_empty_server_token_never_authenticates(client, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "")
    from hunter.settings import get_settings
    get_settings.cache_clear()
    assert client.get("/status", headers={"X-Admin-Token": ""}).status_code == 401


def test_docs_not_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_profiles_and_status(client):
    profiles = client.get("/profiles", headers=H).json()
    assert [p["slug"] for p in profiles] == ["internship-summer-2027", "part-time-europe"]
    status = client.get("/status", headers=H).json()
    assert status["profiles"] == 2 and status["applications"] == 0
    assert status["submission_enabled"] is False


def test_scan_endpoint(client):
    assert client.post("/scan/1", headers=H).json()["state"] == "queued"
    assert client.post("/scan/999", headers=H).status_code == 404


def test_ready_checks_dependencies(client):
    assert client.get("/ready").json() == {"status": "ready"}


def test_ready_fails_when_schema_is_unknown(client, monkeypatch):
    from sqlalchemy import text

    from hunter.db import session_scope
    with session_scope() as db:
        db.execute(text("UPDATE alembic_version SET version_num = 'zz_future'"))
    assert client.get("/ready").status_code == 503
    monkeypatch.setenv("HUNTER_ACCEPT_SCHEMA_REVISION", "zz_future")
    from hunter.settings import get_settings
    get_settings.cache_clear()
    assert client.get("/ready").status_code == 200  # explicitly accepted (verified rollback)
