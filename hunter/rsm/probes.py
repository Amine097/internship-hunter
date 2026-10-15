"""Busy probes: code-defined, read-only HTTP checks. Policy supplies only a local base URL
and a key file; it cannot supply paths, methods or headers. Unknown/unreachable => BUSY."""
import json
import urllib.request
from pathlib import Path

from hunter.rsm.policy import Probe


def _get_json(url: str, header: str, key: str):
    req = urllib.request.Request(url, headers={header: key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - scheme validated
        return json.loads(resp.read(1_000_000))


def jellyfin_playback(probe: Probe, fetch=_get_json) -> tuple[bool, str]:
    key = Path(probe.key_file).read_text().strip()
    sessions = fetch(f"{probe.base_url}/Sessions?ActiveWithinSeconds=90", "X-Emby-Token", key)
    playing = [s for s in sessions if isinstance(s, dict) and s.get("NowPlayingItem")]
    return (bool(playing), f"{len(playing)} active playback session(s)")


def immich_activity(probe: Probe, fetch=_get_json) -> tuple[bool, str]:
    key = Path(probe.key_file).read_text().strip()
    jobs = fetch(f"{probe.base_url}/api/jobs", "x-api-key", key)
    active = 0
    for queue in (jobs.values() if isinstance(jobs, dict) else []):
        counts = queue.get("jobCounts", {}) if isinstance(queue, dict) else {}
        active += int(counts.get("active", 0))
    return (active > 0, f"{active} active Immich job(s)")


RUNNERS = {"jellyfin_playback": jellyfin_playback, "immich_activity": immich_activity}


def run_probe(probe: Probe, runners=RUNNERS) -> tuple[bool, str]:
    """Returns (busy, detail). Any failure to determine activity counts as busy."""
    try:
        return runners[probe.kind](probe)
    except Exception as exc:  # fail closed
        return True, f"probe {probe.name} could not determine activity ({type(exc).__name__})"
