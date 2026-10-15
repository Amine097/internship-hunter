#!/usr/bin/env bash
# Signs a release bundle. Runs in the restricted `sign` job and treats everything produced by
# the build job as UNTRUSTED DATA: nothing from the artifacts is executed, imported, or
# extracted to disk. The signed manifest is generated HERE; the build job's manifest is only
# cross-checked, so a compromised build cannot smuggle schema metadata into a signature.
#
# Usage: deploy/sign-bundle.sh <artifact-dir> <ssh-signing-key> <expected-sha> <out.tar>
set -Eeuo pipefail
dir="${1:?artifact dir}"; key="${2:?key}"; expect="${3:?expected sha}"; out="${4:?out}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die() { echo "sign: $1" >&2; exit 2; }
[[ "$expect" =~ ^[0-9a-f]{40}$ ]] || die "bad expected sha"

for f in manifest source.tar.gz images.tar.gz; do
  [[ -f "$dir/$f" && ! -L "$dir/$f" ]] || die "missing or non-regular: $f"
done
# shellcheck disable=SC2012  # fixed, known names
[[ "$(ls -A "$dir" | LC_ALL=C sort | tr '\n' ' ')" == "images.tar.gz manifest source.tar.gz " ]] \
  || die "unexpected files in artifact dir"

# 1. the source archive is a git archive of exactly the expected commit
gunzip -c "$dir/source.tar.gz" > /dev/null || die "source.tar.gz is not valid gzip"
[[ "$(gunzip -c "$dir/source.tar.gz" | git get-tar-commit-id)" == "$expect" ]] \
  || die "source archive was not produced from commit $expect"

# 2. member types and paths: regular files and directories only
types="$(tar -tvzf "$dir/source.tar.gz" | cut -c1 | sort -u | tr -d '\n')"
[[ "$types" =~ ^[-d]+$ ]] || die "source archive has non-regular members (types: $types)"
if tar -tzf "$dir/source.tar.gz" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
  die "source archive contains unsafe paths"
fi

# 3. deployment scripts must still be executable (git archive preserves the mode)
bad="$(tar -tvzf "$dir/source.tar.gz" | awk '$NF ~ /^deploy\/[^\/]+\.(sh|py)$/ && $1 !~ /^-rwx/ {print $NF}')"
[[ -z "$bad" ]] || die "deploy scripts lost their executable bit: $bad"

# 4. image archive is a gzip stream (its content is never opened here)
gunzip -t "$dir/images.tar.gz" || die "images.tar.gz is not valid gzip"

# 5. schema metadata is RECOMPUTED from the source archive by trusted code (text parsing only)
info="$(python3 "$HERE/schema_info.py" --tar "$dir/source.tar.gz")" || die "schema declaration invalid"
head="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["schema_head"])' "$info")"
compat="$(python3 -c 'import json,sys; print(",".join(json.loads(sys.argv[1])["rollback_compatible"]))' "$info")"
src_hash="$(sha256sum "$dir/source.tar.gz" | cut -d' ' -f1)"
img_hash="$(sha256sum "$dir/images.tar.gz" | cut -d' ' -f1)"

# 6. cross-check the build job's manifest (it must agree, or the build is suspect)
grep -qx "sha=$expect" "$dir/manifest" || die "build manifest sha != $expect"
grep -qx "source_sha256=$src_hash" "$dir/manifest" || die "build manifest source hash mismatch"
grep -qx "images_sha256=$img_hash" "$dir/manifest" || die "build manifest images hash mismatch"
grep -qx "schema_head=$head" "$dir/manifest" \
  || die "build manifest schema_head disagrees with the source archive"
grep -qx "rollback_compatible=$compat" "$dir/manifest" \
  || die "build manifest rollback_compatible disagrees with the source archive"

# 7. generate and sign the authoritative manifest
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
printf 'sha=%s\nsource_sha256=%s\nimages_sha256=%s\ncreated=%s\nschema_head=%s\nrollback_compatible=%s\n' \
  "$expect" "$src_hash" "$img_hash" "$(date +%s)" "$head" "$compat" > "$work/manifest"
cp "$dir/source.tar.gz" "$dir/images.tar.gz" "$work/"
ssh-keygen -q -Y sign -f "$key" -n hunter-release "$work/manifest"
tar -cf "$out" -C "$work" manifest manifest.sig source.tar.gz images.tar.gz
echo "signed bundle: $out (schema_head=$head rollback_compatible=${compat:-none})"
