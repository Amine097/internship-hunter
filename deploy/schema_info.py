#!/usr/bin/env python3
"""Prints {"schema_head": ..., "rollback_compatible": [...]} for a source tree.

Stdlib only (runs on a bare CI runner and on the server): the Alembic head is the revision
no other revision names as its ``down_revision``.
Usage: schema_info.py <source-root>
"""
import json
import re
import sys
from pathlib import Path


def info(root: Path) -> dict:
    versions = root / "hunter" / "migrations" / "versions"
    revs, downs = {}, set()
    for f in sorted(versions.glob("*.py")):
        text = f.read_text()
        rev = re.search(r'^revision\s*=\s*"([0-9A-Za-z_]+)"', text, re.M)
        down = re.search(r'^down_revision\s*=\s*(None|"([0-9A-Za-z_]+)")', text, re.M)
        if rev and down:
            revs[rev.group(1)] = down.group(2)
            if down.group(2):
                downs.add(down.group(2))
    heads = [r for r in revs if r not in downs]
    if len(heads) != 1:
        raise SystemExit(f"expected exactly one migration head, found {heads}")
    compat = json.loads((root / "hunter" / "migrations" / "compat.json").read_text())
    listed = compat.get("rollback_compatible_with", [])
    unknown = [r for r in listed if r not in revs]
    if unknown:
        raise SystemExit(f"compat.json names unknown revisions: {unknown}")
    return {"schema_head": heads[0], "rollback_compatible": listed}


if __name__ == "__main__":
    print(json.dumps(info(Path(sys.argv[1]))))
