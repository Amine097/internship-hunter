#!/usr/bin/env bash
# Builds a signed, immutable release bundle for one commit (run on a CI runner, not the server).
# Usage: deploy/make-bundle.sh <40-hex-sha> <ssh-signing-key> <out.tar>
# Contents: source.tar.gz (git archive), images.tar.gz (docker save, tagged by SHA),
#           manifest (sha + sha256 of both archives + creation time) and manifest.sig.
set -Eeuo pipefail
sha="${1:?sha}"; key="${2:?signing key}"; out="${3:?output path}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "sha must be a full 40-hex commit id" >&2; exit 2; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

git archive --format=tar.gz -o "$work/source.tar.gz" "$sha"
mkdir "$work/src" && tar -xzf "$work/source.tar.gz" -C "$work/src"
docker build -q -f "$work/src/docker/app.Dockerfile"   -t "internship-hunter-app:$sha"   "$work/src"
docker build -q -f "$work/src/docker/agent.Dockerfile" -t "internship-hunter-agent:$sha" "$work/src"
docker save "internship-hunter-app:$sha" "internship-hunter-agent:$sha" | gzip -n > "$work/images.tar.gz"

printf 'sha=%s\nsource_sha256=%s\nimages_sha256=%s\ncreated=%s\n' \
  "$sha" \
  "$(sha256sum "$work/source.tar.gz" | cut -d' ' -f1)" \
  "$(sha256sum "$work/images.tar.gz" | cut -d' ' -f1)" \
  "$(date +%s)" > "$work/manifest"
ssh-keygen -q -Y sign -f "$key" -n hunter-release "$work/manifest"

tar -cf "$out" -C "$work" manifest manifest.sig source.tar.gz images.tar.gz
echo "bundle: $out ($(du -h "$out" | cut -f1))"
