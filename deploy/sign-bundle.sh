#!/usr/bin/env bash
# Signs a bundle. Runs in the restricted `sign` job: it must NOT execute anything from the
# artifacts (no docker, no scripts, no extraction) - it only hashes and verifies them.
# Usage: deploy/sign-bundle.sh <artifact-dir> <ssh-signing-key> <expected-sha> <out.tar>
set -Eeuo pipefail
dir="${1:?artifact dir}"; key="${2:?key}"; expect="${3:?expected sha}"; out="${4:?out}"
[[ "$expect" =~ ^[0-9a-f]{40}$ ]] || { echo "bad expected sha" >&2; exit 2; }
for f in manifest source.tar.gz images.tar.gz; do
  [[ -f "$dir/$f" && ! -L "$dir/$f" ]] || { echo "missing or non-regular: $f" >&2; exit 2; }
done
# shellcheck disable=SC2012  # fixed, known names
[[ "$(ls -A "$dir" | LC_ALL=C sort | tr '\n' ' ')" == "images.tar.gz manifest source.tar.gz " ]] \
  || { echo "unexpected files in artifact dir" >&2; exit 2; }
[[ "$(wc -l < "$dir/manifest")" -eq 6 ]] || { echo "manifest must have 6 lines" >&2; exit 2; }
grep -qx "sha=$expect" "$dir/manifest" || { echo "manifest sha != $expect" >&2; exit 2; }
grep -qx "source_sha256=$(sha256sum "$dir/source.tar.gz" | cut -d' ' -f1)" "$dir/manifest" \
  || { echo "source hash mismatch" >&2; exit 2; }
grep -qx "images_sha256=$(sha256sum "$dir/images.tar.gz" | cut -d' ' -f1)" "$dir/manifest" \
  || { echo "images hash mismatch" >&2; exit 2; }
grep -Eq '^schema_head=[0-9A-Za-z_]{1,32}$' "$dir/manifest" || { echo "bad schema_head" >&2; exit 2; }
grep -Eq '^created=[0-9]{10}$' "$dir/manifest" || { echo "bad created" >&2; exit 2; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$dir/manifest" "$dir/source.tar.gz" "$dir/images.tar.gz" "$work/"
ssh-keygen -q -Y sign -f "$key" -n hunter-release "$work/manifest"
tar -cf "$out" -C "$work" manifest manifest.sig source.tar.gz images.tar.gz
echo "signed bundle: $out"
