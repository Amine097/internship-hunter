"""Strict schemas for everything that crosses the agent trust boundary.

Agent containers are untrusted: what they return is data, validated here by trusted code
before it is stored. What we send them is limited to a fixed set of profile fields.
"""
import re
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

AgentName = Literal["claude-1", "claude-2", "codex"]
MAX_RESPONSE_BYTES = 32_768
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

Query = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]
Role = Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,40}$")]
Country = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]


class AgentPlan(BaseModel):
    """Reply of an agent runner. Unknown fields are rejected, not ignored."""
    model_config = ConfigDict(extra="forbid")

    agent: AgentName
    mode: Literal["demo", "cli"]
    queries: Annotated[list[Query], Field(max_length=15)]
    note: Annotated[str, StringConstraints(max_length=200)] | None = None

    @field_validator("queries")
    @classmethod
    def _no_control_chars(cls, queries: list[str]) -> list[str]:
        if any(_CONTROL.search(q) for q in queries):
            raise ValueError("control characters in query")
        return queries


class AgentProfile(BaseModel):
    """The only profile fields an agent ever receives."""
    model_config = ConfigDict(extra="ignore")

    kind: Literal["internship", "part_time"]
    roles: Annotated[list[Role], Field(max_length=20)] = []
    primary_countries: Annotated[list[Country], Field(max_length=60)] = []
    secondary_countries: Annotated[list[Country], Field(max_length=60)] = []
    earliest_start: date | None = None
    latest_start: date | None = None
    min_duration_months: Annotated[int, Field(ge=0, le=36)] | None = None
    max_duration_months: Annotated[int, Field(ge=0, le=36)] | None = None
    min_hours_per_week: Annotated[int, Field(ge=0, le=80)] | None = None
    max_hours_per_week: Annotated[int, Field(ge=0, le=80)] | None = None


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: AgentProfile
