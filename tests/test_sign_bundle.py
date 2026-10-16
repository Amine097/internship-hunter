"""The signing job must trust nothing the build job produced: it recomputes schema metadata
from the source archive, and refuses anything that disagrees or is malformed."""
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SIGN = ROOT / "deploy" / "sign-bundle.sh"
SHA = "c" * 40
MIGRATIONS = {
    "0001_a.py": 'revision = "0001"\ndown_revision = None\n',
    "0002_b.py": 'revision = "0002"\ndown_revision = "0001"\n',
    "0003_c.py": 'revision = "0003"\ndown_revision = "0002"\n',
    "0004_d.py": 'revision = "0004"\ndown_revision = "0003"\n',
}


def compat_json(since="0003", listed=("0003",)):
    return json.dumps({"accept_protocol_since": since, "rollback_compatible_with": list(listed)})


def source_tar(path: Path, sha=SHA, compat=None, migrations=MIGRATIONS, symlink=False,
               script_mode=0o755):
    compat = compat if compat is not None else compat_json()
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": sha}) as t:
        def add(name, data, mode=0o644):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), mode
            t.addfile(ti, io.BytesIO(data))
        for n, body in migrations.items():
            add(f"hunter/migrations/versions/{n}", body.encode())
        add("hunter/migrations/compat.json", compat.encode())
        add("deploy/remote-deploy.sh", b"#!/bin/sh\n", script_mode)
        if symlink:
            ti = tarfile.TarInfo("link")
            ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
            t.addfile(ti)


@pytest.fixture
def keys(tmp_path):
    k = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
    return k


def build_dir(tmp_path, *, head="0004", compat="0003", compat_file=None, **src_kw):
    d = tmp_path / "artifacts"
    d.mkdir()
    source_tar(d / "source.tar.gz", compat=compat_file, **src_kw)
    (d / "images.tar.gz").write_bytes(gzip.compress(b"fake docker save"))
    src_hash = hashlib.sha256((d / "source.tar.gz").read_bytes()).hexdigest()
    img_hash = hashlib.sha256((d / "images.tar.gz").read_bytes()).hexdigest()
    manifest = (f"sha={SHA}\nsource_sha256={src_hash}\nimages_sha256={img_hash}\n"
                f"created=1900000000\nschema_head={head}\nrollback_compatible={compat}\n")
    (d / "manifest").write_text(manifest)
    return d


def sign(d, key, out, sha=SHA):
    return subprocess.run(["bash", str(SIGN), str(d), str(key), sha, str(out)],
                          capture_output=True, text=True)


def test_good_bundle_is_signed_with_recomputed_manifest(tmp_path, keys):
    d = build_dir(tmp_path)
    out = tmp_path / "bundle.tar"
    r = sign(d, keys, out)
    assert r.returncode == 0, r.stderr
    with tarfile.open(out) as t:
        names = sorted(t.getnames())
        manifest = t.extractfile("manifest").read().decode()
    assert names == ["images.tar.gz", "manifest", "manifest.sig", "source.tar.gz"]
    assert "schema_head=0004\nrollback_compatible=0003\n" in manifest
    assert len(manifest.splitlines()) == 6


@pytest.mark.parametrize("head,compat,why", [
    ("0003", "0003", "schema_head"),          # build job lies about the head
    ("0004", "", "rollback_compatible"),      # build job hides the declaration
    ("0004", "0003,0002", "rollback_compatible"),  # build job widens it
])
def test_build_job_cannot_smuggle_schema_metadata(tmp_path, keys, head, compat, why):
    d = build_dir(tmp_path, head=head, compat=compat)
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and why in r.stderr
    assert not (tmp_path / "b.tar").exists()


def test_declaration_naming_a_pre_protocol_release_is_not_signable(tmp_path, keys):
    d = build_dir(tmp_path, compat="0002",
                  compat_file=compat_json(since="0003", listed=("0002",)))
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and "predates accept_protocol_since" in r.stderr


def test_unknown_revision_in_declaration_is_not_signable(tmp_path, keys):
    d = build_dir(tmp_path, compat="0009", compat_file=compat_json(listed=("0009",)))
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and "unknown revision" in r.stderr


def test_two_heads_are_not_signable(tmp_path, keys):
    forked = {**MIGRATIONS, "0004_e.py": 'revision = "0005"\ndown_revision = "0003"\n'}
    d = build_dir(tmp_path, migrations=forked)
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and "exactly one migration head" in r.stderr


def test_source_archive_must_come_from_the_expected_commit(tmp_path, keys):
    d = build_dir(tmp_path, sha="d" * 40)
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and "not produced from commit" in r.stderr


def test_non_regular_members_are_rejected(tmp_path, keys):
    d = build_dir(tmp_path, symlink=True)
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and "non-regular" in r.stderr


def test_deploy_scripts_must_stay_executable(tmp_path, keys):
    d = build_dir(tmp_path, script_mode=0o644)
    r = sign(d, keys, tmp_path / "b.tar")
    assert r.returncode == 2 and "executable bit" in r.stderr


def test_hash_mismatch_and_foreign_files_are_rejected(tmp_path, keys):
    d = build_dir(tmp_path)
    (d / "images.tar.gz").write_bytes(gzip.compress(b"tampered after hashing"))
    assert sign(d, keys, tmp_path / "b.tar").returncode == 2
    d2 = tmp_path / "a2"
    d2.mkdir()
    for f in (tmp_path / "artifacts").iterdir():
        (d2 / f.name).write_bytes(f.read_bytes())
    (d2 / "extra.sh").write_text("echo")
    assert "unexpected files" in sign(d2, keys, tmp_path / "c.tar").stderr


def test_signing_script_never_executes_or_extracts_artifacts():
    src = SIGN.read_text()
    code = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
    text = "\n".join(code)
    assert "docker " not in text and "docker\n" not in text
    assert "tar -x" not in text and "tar -C" not in text.replace("tar -cf", "")
    assert not re.search(r"^\s*(source|\.)\s", text, re.M)   # never sources artifact files
    assert "bash \"$dir" not in text
