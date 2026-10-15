"""Public ATS discovery only; no authentication, scraping bypass or submissions."""
import hashlib
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

import httpx
import yaml


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self.chunks.append(data)


def strip_html(raw: str | None) -> str:
    parser = TextOnly()
    parser.feed(raw or "")
    return " ".join(unescape(" ".join(parser.chunks)).split())


def canonical_key(source: str, board: str, external_id: str) -> str:
    return hashlib.sha256(f"{source}:{board}:{external_id}".encode()).hexdigest()


def allowed_board_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name))


def read_sources(path: str) -> list[dict]:
    content = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    sources = content.get("sources", [])
    if not isinstance(sources, list):
        raise ValueError("sources must be a list")
    for source in sources:
        if source.get("kind") not in ("greenhouse", "lever"):
            raise ValueError("Only public Greenhouse or Lever source types are allowed in V1")
        if not allowed_board_name(str(source.get("token", ""))):
            raise ValueError("Invalid ATS board handle")
    return sources


def fetch_source(source: dict, client: httpx.Client) -> list[dict]:
    kind = source["kind"]
    token = source["token"]
    if kind not in ("greenhouse", "lever") or not allowed_board_name(token):
        raise ValueError("Invalid source")
    if kind == "greenhouse":
        url = f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true"
        response = client.get(url)
        response.raise_for_status()
        return [
            {
                "canonical_key": canonical_key(kind, token, str(job["id"])),
                "source": kind,
                "source_url": job["absolute_url"],
                "title": job["title"],
                "company": token,
                "location": job.get("location", {}).get("name", ""),
                "description": strip_html(job.get("content", "")),
            }
            for job in response.json().get("jobs", [])
        ]
    response = client.get(f"https://api.lever.co/v0/postings/{token}?mode=json")
    response.raise_for_status()
    return [
        {
            "canonical_key": canonical_key(kind, token, str(job["id"])),
            "source": kind,
            "source_url": job["hostedUrl"],
            "title": job["text"],
            "company": token,
            "location": job.get("categories", {}).get("location", ""),
            "description": strip_html(job.get("descriptionPlain") or job.get("description")),
        }
        for job in response.json()
    ]


def fetch_all(sources: list[dict]) -> tuple[list[dict], list[str]]:
    found: dict[str, dict] = {}
    errors: list[str] = []
    with httpx.Client(timeout=12.0, follow_redirects=False) as client:
        for source in sources:
            try:
                for job in fetch_source(source, client):
                    found[job["canonical_key"]] = job
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                errors.append(f"{source['kind']}:{source['token']}: {type(exc).__name__}")
    return list(found.values()), errors
