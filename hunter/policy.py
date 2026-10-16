"""Conservative eligibility triage. Uncertainty is not a reason for rejection."""
from datetime import date
from typing import Literal

Decision = Literal["eligible", "uncertain", "hard_reject"]

# Milestone 1 hard stop: nothing in this codebase may submit an application or send email.
SUBMISSION_ENABLED = False


def duration_decision(
    requested_min: int | None,
    requested_max: int | None,
    offered_min: int | None,
    offered_max: int | None,
) -> Decision:
    if offered_min is None or offered_max is None or offered_min > offered_max:
        return "uncertain"
    if requested_min is None or requested_max is None:
        return "eligible"
    if offered_min > requested_max or offered_max < requested_min:
        return "hard_reject"
    return "eligible"


def dates_decision(
    requested_earliest: date | None,
    requested_latest: date | None,
    offered_earliest: date | None,
    offered_latest: date | None,
) -> Decision:
    """A ``None`` requested bound is open-ended; unknown *offered* dates are uncertain.

    A single known offered date is treated as a point in time.
    """
    if requested_earliest is None and requested_latest is None:
        return "eligible"
    if offered_earliest is None and offered_latest is None:
        return "uncertain"
    if offered_earliest and offered_latest and offered_earliest > offered_latest:
        return "uncertain"  # reversed range is a data error, never a rejection
    low = offered_earliest or offered_latest
    high = offered_latest or offered_earliest
    if requested_latest is not None and low > requested_latest:
        return "hard_reject"
    if requested_earliest is not None and high < requested_earliest:
        return "hard_reject"
    return "eligible"


def combine(decisions: list[Decision]) -> Decision:
    if "hard_reject" in decisions:
        return "hard_reject"
    if "uncertain" in decisions:
        return "uncertain"
    return "eligible"
