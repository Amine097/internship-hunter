import httpx
import pytest

from hunter.sources import allowed_board_name, canonical_key, fetch_source, read_sources, strip_html


def test_stable_normalized_id():
    assert canonical_key("lever", "team", "123") == canonical_key("lever", "team", "123")
    assert canonical_key("lever", "team", "123") != canonical_key("lever", "team", "124")


def test_board_handles_are_not_urls():
    assert allowed_board_name("company-board")
    assert not allowed_board_name("https://evil.example/jobs")
    assert not allowed_board_name("../etc/passwd")


def test_html_extraction():
    assert strip_html("<p>Work <strong>on Linux</strong></p>") == "Work on Linux"


def test_greenhouse_public_response():
    def handler(request):
        assert request.url.host == "boards-api.greenhouse.io"
        return httpx.Response(200, json={"jobs": [{"id": 42, "title": "Systems Intern",
            "absolute_url": "https://boards.greenhouse.io/org/jobs/42",
            "location": {"name": "Zurich"}, "content": "<p>Linux</p>"}]})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = fetch_source({"kind": "greenhouse", "token": "org"}, client)
    assert result[0]["title"] == "Systems Intern"
    assert result[0]["location"] == "Zurich"
    assert result[0]["description"] == "Linux"


def test_lever_public_response():
    def handler(request):
        assert request.url.host == "api.lever.co"
        return httpx.Response(200, json=[{"id": "aa", "text": "Student Software Engineer",
            "hostedUrl": "https://jobs.lever.co/org/aa", "categories": {"location": "Remote"},
            "descriptionPlain": "part time engineering"}])
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = fetch_source({"kind": "lever", "token": "org"}, client)
    assert result[0]["source"] == "lever"
    assert result[0]["location"] == "Remote"


def test_reject_invalid_source(tmp_path):
    f = tmp_path / "sources.yaml"
    f.write_text("sources:\n  - kind: lever\n    token: 'http://localhost:8080'\n")
    with pytest.raises(ValueError):
        read_sources(str(f))
