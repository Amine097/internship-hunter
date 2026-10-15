from datetime import date

from hunter.policy import combine, dates_decision, duration_decision


def test_unknown_duration_not_rejected():
    assert duration_decision(2, 3, None, None) == "uncertain"


def test_duration_incompatible():
    assert duration_decision(2, 3, 5, 6) == "hard_reject"


def test_duration_overlap():
    assert duration_decision(2, 3, 3, 6) == "eligible"


def test_unknown_start_is_not_rejected():
    assert dates_decision(date(2027, 7, 1), date(2027, 8, 1), None, None) == "uncertain"


def test_incompatible_start():
    assert dates_decision(
        date(2027, 7, 1), date(2027, 8, 1), date(2027, 10, 1), date(2027, 11, 1),
    ) == "hard_reject"


def test_overlap():
    assert dates_decision(
        date(2027, 7, 1), date(2027, 8, 1), date(2027, 7, 15), date(2027, 7, 15),
    ) == "eligible"


def test_combine():
    assert combine(["eligible", "uncertain"]) == "uncertain"
    assert combine(["uncertain", "hard_reject"]) == "hard_reject"
