import time
from datetime import date

import httpx

from hunter.policy import dates_decision
from hunter.sources import fetch_all, fetch_source, make_client

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


def test_unexpected_shape_is_reported_not_raised():
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"error": "x"}))
    jobs, errors = fetch_all([{"kind": "lever", "token": "o"}], transport=transport)
    assert jobs == [] and errors == ["lever:o: ValueError"]


def test_oversized_ats_body_is_rejected(monkeypatch):
    monkeypatch.setattr("hunter.sources.MAX_BODY_BYTES", 1000)
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=b"[" + b"1," * 2000))
    jobs, errors = fetch_all([{"kind": "lever", "token": "o"}], transport=transport)
    assert jobs == [] and errors == ["lever:o: ValueError"]


def test_scan_deadline_skips_remaining_sources():
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=[]))
    jobs, errors = fetch_all(
        [{"kind": "lever", "token": "a"}, {"kind": "lever", "token": "b"}],
        deadline=time.monotonic() - 1, transport=transport,
    )
    assert jobs == [] and len(errors) == 2 and all("deadline" in e for e in errors)


def test_fetch_all_client_does_not_follow_redirects():
    """Tests the client fetch_all really builds, not httpx's default."""
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    assert make_client().follow_redirects is False
    jobs, errors = fetch_all([{"kind": "greenhouse", "token": "o"}],
                             transport=httpx.MockTransport(handler))
    assert jobs == [] and errors == ["greenhouse:o: HTTPStatusError"]
    assert len(seen) == 1  # the redirect target was never requested


def test_reversed_ranges_are_uncertain_not_rejected():
    from hunter.policy import duration_decision
    assert dates_decision(D(2027, 7, 1), D(2027, 8, 1), D(2027, 9, 1), D(2027, 7, 1)) == \
        "uncertain"
    assert duration_decision(2, 3, 6, 2) == "uncertain"


def test_no_requested_dates_means_no_constraint():
    assert dates_decision(None, None, D(2027, 1, 1), None) == "eligible"
