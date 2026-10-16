#!/usr/bin/env python3
"""Computes {"schema_head", "rollback_compatible"} for a source tree or a source archive.

Stdlib only and *text parsing only*: nothing from the inspected tree is imported or executed,
so the signing job can run it on untrusted artifacts.

Usage: schema_info.py <source-root>
       schema_info.py --tar <source.tar.gz>
Exit status 1 with a message if the declaration is invalid:
  * not exactly one migration head
  * compat.json names an unknown revision
  * compat.json names a revision older than ``accept_protocol_since`` (a release that cannot
    accept a newer schema must never be declared rollback-compatible)
"""
import json
import re
import sys
import tarfile
from pathlib import Path

VERSIONS = "hunter/migrations/versions/"
COMPAT = "hunter/migrations/compat.json"
REV = re.compile(r'^revision\s*=\s*"([0-9A-Za-z_]{1,32})"', re.M)
DOWN = re.compile(r'^down_revision\s*=\s*(None|"([0-9A-Za-z_]{1,32})")', re.M)


def _read_tree(root: Path) -> tuple[dict[str, str], str]:
    files = {f.name: f.read_text() for f in sorted((root / VERSIONS).glob("*.py"))}
    return files, (root / COMPAT).read_text()


def _read_tar(path: Path) -> tuple[dict[str, str], str]:
    files, compat = {}, None
    with tarfile.open(path, "r:gz") as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            name = m.name.removeprefix("./")
            rest = name[len(VERSIONS):]
            if name.startswith(VERSIONS) and rest.endswith(".py") and "/" not in rest:
                files[rest] = tar.extractfile(m).read().decode()
            elif name == COMPAT:
                compat = tar.extractfile(m).read().decode()
    if compat is None:
        raise SystemExit(f"{COMPAT} missing from archive")
    return files, compat


def compute(files: dict[str, str], compat_text: str) -> dict:
    revs: dict[str, str | None] = {}
    for text in files.values():
        rev, down = REV.search(text), DOWN.search(text)
        if rev and down:
            revs[rev.group(1)] = down.group(2)
    downs = {d for d in revs.values() if d}
    heads = [r for r in revs if r not in downs]
    if len(heads) != 1:
        raise SystemExit(f"expected exactly one migration head, found {heads}")
    compat = json.loads(compat_text)
    since = compat.get("accept_protocol_since")
    if since not in revs:
        raise SystemExit(f"accept_protocol_since {since!r} is not a known revision")
    chain, node = [], heads[0]          # head -> ... -> base
    while node is not None:
        chain.append(node)
        node = revs[node]
    allowed = set(chain[: chain.index(since) + 1]) if since in chain else set()
    listed = compat.get("rollback_compatible_with", [])
    for r in listed:
        if r not in revs:
            raise SystemExit(f"compat.json names unknown revision {r!r}")
        if r not in allowed:
            raise SystemExit(
                f"compat.json lists {r!r}, which predates accept_protocol_since={since!r}: "
                "such releases cannot accept a newer schema")
        if r == heads[0]:
            raise SystemExit("a release cannot list its own head")
    return {"schema_head": heads[0], "rollback_compatible": listed}


def info(root: Path) -> dict:
    return compute(*_read_tree(root))


def info_from_tar(path: Path) -> dict:
    return compute(*_read_tar(path))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--tar":
        print(json.dumps(info_from_tar(Path(sys.argv[2]))))
    elif len(sys.argv) == 2:
        print(json.dumps(info(Path(sys.argv[1]))))
    else:
        raise SystemExit(__doc__)
