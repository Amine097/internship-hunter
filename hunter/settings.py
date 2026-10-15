from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./hunter-local.db"
    redis_url: str = "redis://redis:6379/0"
    admin_token: str = ""
    telegram_bot_token: str = ""
    telegram_allowed_user_id: str = ""
    agent_mode: Literal["demo", "cli"] = "demo"
    scan_cron: str = "0 7,13,20 * * *"
    tz: str = "Europe/Zurich"
    # Agent-container identity (agent runners only)
    hunter_agent_name: str = ""
    agent_token: str = ""
    # Orchestrator -> agent endpoints and their inbound tokens (trusted side only)
    agent_url_claude_1: str = "http://agent-claude-1:8100"
    agent_url_claude_2: str = "http://agent-claude-2:8100"
    agent_url_codex: str = "http://agent-codex:8100"
    agent_token_claude_1: str = ""
    agent_token_claude_2: str = ""
    agent_token_codex: str = ""
    profiles_path: str = "config/search_profiles.yaml"
    sources_path: str = "config/sources.yaml"


@lru_cache
def get_settings() -> Settings:
    return Settings()
