from datetime import date

import httpx
import pytest

from hunter.policy import dates_decision
from hunter.sources import fetch_all, fetch_source

D = date


def test_open_ended_part_time_window():
    # part-time profile: earliest 2026-10-14, no latest start
    assert dates_decision(D(2026, 10, 14), None, D(2026, 12, 1), None) == "eligible"
    assert dates_decision(D(2026, 10, 14), None, D(2026, 9, 1), None) == "hard_reject"
    assert dates_decision(D(2026, 10, 14), None, None, None) == "uncertain"


def test_single_offered_date_is_a_point():
    assert dates_decision(D(2027, 7, 1), D(2027, 8, 1), D(2027, 7, 15), None) == "eligible"
    assert dates_decision(D(2027, 7, 1), D(2027, 8, 1), D(2027, 9, 1), None) == "hard_reject"


def _client(payload):
    return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload)))


def test_malformed_posting_does_not_drop_board():
    payload = {"jobs": [
        {"id": 1, "title": "Good", "absolute_url": "https://boards.greenhouse.io/o/1",
         "location": None, "content": None},
        {"id": 2, "title": "No url"},
        {"id": 3, "title": "Bad scheme", "absolute_url": "javascript:alert(1)"},
        "garbage",
    ]}
    with _client(payload) as c:
        jobs = fetch_source({"kind": "greenhouse", "token": "o"}, c)
    assert [j["title"] for j in jobs] == ["Good"]
    assert jobs[0]["location"] == ""


def test_fields_clipped_to_column_sizes():
    payload = [{"id": "x", "text": "T" * 900, "hostedUrl": "https://jobs.lever.co/o/x",
                "categories": {"location": "L" * 900}, "descriptionPlain": "a\x00b"}]
    with _client(payload) as c:
        job = fetch_source({"kind": "lever", "token": "o"}, c)[0]
    assert len(job["title"]) == 350 and len(job["location"]) == 250
    assert "\x00" not in job["description"]


def test_unexpected_shape_is_reported_not_raised(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"error": "x"})

    real = httpx.Client
    monkeypatch.setattr(
        "hunter.sources.httpx.Client",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )
    jobs, errors = fetch_all([{"kind": "lever", "token": "o"}])
    assert jobs == [] and errors == ["lever:o: ValueError"]


def test_greenhouse_redirect_not_followed():
    with pytest.raises(httpx.HTTPStatusError):
        c = httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(302, headers={"location": "http://internal/"})))
        fetch_source({"kind": "greenhouse", "token": "o"}, c)
