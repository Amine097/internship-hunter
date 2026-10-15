"""Schema/rollback compatibility: unknown revisions are never silently ignored, and
migrations inside the declared rollback window are expand-only."""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

from hunter import db as db_module
from hunter.db import SchemaMismatch, session_scope
from hunter.settings import get_settings

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "hunter" / "migrations" / "versions"
COMPAT = json.loads((ROOT / "hunter" / "migrations" / "compat.json").read_text())


def set_revision(rev):
    with session_scope() as db:
        db.execute(text("UPDATE alembic_version SET version_num = :r"), {"r": rev})


def test_unknown_revision_fails_loudly_and_changes_nothing(any_db):
    set_revision("zz_from_the_future")
    with pytest.raises(SchemaMismatch, match="zz_from_the_future"):
        db_module.run_migrations()
    with pytest.raises(SchemaMismatch):
        db_module.init_db()
    with session_scope() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "zz_from_the_future"
    assert db_module.schema_state()[0] == "unknown"


def test_accepted_revision_is_explicit_and_never_migrates_or_seeds(any_db, monkeypatch):
    set_revision("zz_from_the_future")
    with session_scope() as db:
        db.execute(text("UPDATE search_profiles SET name = 'untouched'"))
    monkeypatch.setenv("HUNTER_ACCEPT_SCHEMA_REVISION", "zz_from_the_future")
    get_settings.cache_clear()
    assert db_module.schema_state()[0] == "accepted"
    db_module.init_db()                      # no exception, no migration, no seeding
    with session_scope() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "zz_from_the_future"
        assert db.scalar(text("SELECT DISTINCT name FROM search_profiles")) == "untouched"


def test_accepting_a_different_revision_does_not_help(any_db, monkeypatch):
    set_revision("zz_from_the_future")
    monkeypatch.setenv("HUNTER_ACCEPT_SCHEMA_REVISION", "something_else")
    get_settings.cache_clear()
    with pytest.raises(SchemaMismatch):
        db_module.run_migrations()


def test_known_older_revision_is_reported_as_behind(any_db):
    set_revision("0002")
    assert db_module.schema_state()[0] == "behind"


def test_schema_info_matches_alembic():
    out = subprocess.run([sys.executable, str(ROOT / "deploy" / "schema_info.py"), str(ROOT)],
                         capture_output=True, text=True, check=True).stdout
    info = json.loads(out)
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "hunter" / "migrations"))
    assert info["schema_head"] == ScriptDirectory.from_config(cfg).get_current_head()
    assert info["rollback_compatible"] == COMPAT["rollback_compatible_with"]


FORBIDDEN = re.compile(
    r"op\.(drop_table|drop_column|drop_index|drop_constraint|alter_column|rename_table|"
    r"execute\(\s*[\"']\s*(DROP|ALTER TABLE .* (DROP|RENAME)))", re.I)
FORBIDDEN_BATCH = re.compile(r"batch\.(drop_column|drop_constraint|alter_column)")


def _upgrade_body(path: Path) -> str:
    src = path.read_text()
    start = src.index("def upgrade()")
    end = src.index("def downgrade()") if "def downgrade()" in src else len(src)
    return src[start:end]


def _chain():
    revs = {}
    for f in VERSIONS.glob("*.py"):
        t = f.read_text()
        rev = re.search(r'^revision = "(\w+)"', t, re.M)
        if rev is None:
            continue  # __init__.py
        down = re.search(r'^down_revision = (None|"(\w+)")', t, re.M).group(2)
        revs[rev.group(1)] = (down, f)
    return revs


def test_every_migration_after_a_compatible_base_is_expand_only():
    """If compat.json says release@<base> still runs on our head, everything between the
    base and head must be additive. This is the machine-checked half of the policy."""
    revs = _chain()
    for base in COMPAT["rollback_compatible_with"]:
        downs = {d for d, _ in revs.values()}
        node = next(r for r in revs if r not in downs)  # the head
        while node != base:
            down, path = revs[node]
            body = _upgrade_body(path)
            assert not FORBIDDEN.search(body) and not FORBIDDEN_BATCH.search(body), (
                f"{path.name} is not expand-only but compat.json declares rollback to {base}")
            node = down
            assert node is not None, f"base {base} is not an ancestor of head"


def test_lint_catches_a_contracting_migration(tmp_path):
    bad = tmp_path / "0099_x.py"
    bad.write_text('revision = "0099"\ndown_revision = "0003"\n'
                   "def upgrade():\n    op.drop_column('scans', 'error')\n"
                   "def downgrade():\n    pass\n")
    assert FORBIDDEN.search(_upgrade_body(bad))


# --- accept-protocol baseline (compat.json must not promise what old releases cannot do) ---

def test_compat_json_does_not_list_releases_without_the_accept_protocol():
    since = COMPAT["accept_protocol_since"]
    assert since == "0003"                      # first release implementing the protocol
    assert "0002" not in COMPAT["rollback_compatible_with"]
    assert "0001" not in COMPAT["rollback_compatible_with"]
    assert since in _chain()


def test_every_declared_revision_is_at_or_after_the_protocol_baseline():
    sys.path.insert(0, str(ROOT / "deploy"))
    import schema_info
    assert schema_info.info(ROOT)["rollback_compatible"] == COMPAT["rollback_compatible_with"]


def test_schema_info_rejects_pre_protocol_declarations(tmp_path):
    import shutil
    tree = tmp_path / "t"
    shutil.copytree(ROOT / "hunter" / "migrations", tree / "hunter" / "migrations")
    (tree / "hunter" / "migrations" / "compat.json").write_text(json.dumps(
        {"accept_protocol_since": "0003", "rollback_compatible_with": ["0002"]}))
    r = subprocess.run([sys.executable, str(ROOT / "deploy" / "schema_info.py"), str(tree)],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "predates accept_protocol_since" in r.stderr
