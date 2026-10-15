import json

import pytest

from hunter.agents import AGENTS, demo_plan, parse_plan


@pytest.fixture
def profile():
    return {
        "kind": "internship", "roles": ["systems", "backend", "sre"],
        "primary_countries": ["CH"], "secondary_countries": ["DE", "FR"],
    }


def test_three_planners_independent(profile):
    plans = [demo_plan(agent, profile) for agent in AGENTS]
    assert len({plan["agent"] for plan in plans}) == 3
    assert all(plan["queries"] for plan in plans)
    assert plans[0]["queries"] != plans[1]["queries"]


def test_parse_only_queries():
    plan = parse_plan(json.dumps({"queries": ["engineer CH", 42, "backend DE"]}), "codex")
    assert plan["queries"] == ["engineer CH", "backend DE"]


def test_invalid_agent_output():
    with pytest.raises(ValueError):
        parse_plan('["not an object"]', "codex")
