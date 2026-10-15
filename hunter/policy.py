"""Conservative eligibility triage. Uncertainty is not a reason for rejection."""
from datetime import date
from typing import Literal

Decision = Literal["eligible", "uncertain", "hard_reject"]


def duration_decision(
    requested_min: int | None,
    requested_max: int | None,
    offered_min: int | None,
    offered_max: int | None,
) -> Decision:
    if offered_min is None or offered_max is None:
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
    if requested_earliest is None or requested_latest is None:
        return "uncertain"
    if offered_earliest is None or offered_latest is None:
        return "uncertain"
    if offered_earliest > requested_latest or offered_latest < requested_earliest:
        return "hard_reject"
    return "eligible"


def combine(decisions: list[Decision]) -> Decision:
    if "hard_reject" in decisions:
        return "hard_reject"
    if "uncertain" in decisions:
        return "uncertain"
    return "eligible"
