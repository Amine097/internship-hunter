#!/usr/bin/env bash
# Builds the UNSIGNED release artifacts for one commit. Needs no secrets: this is the part
# that executes repository code (docker build), so it must never see the signing key.
# Usage: deploy/build-artifacts.sh <40-hex-sha> <outdir>
# Output: source.tar.gz, images.tar.gz (docker save, tagged by SHA), manifest (6 lines)
set -Eeuo pipefail
sha="${1:?sha}"; out="${2:?output dir}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "sha must be a full 40-hex commit id" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$out"; out="$(cd "$out" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

git archive --format=tar.gz -o "$out/source.tar.gz" "$sha"

# deployment scripts must keep their executable bit through git archive
bad="$(tar -tvzf "$out/source.tar.gz" | awk '$NF ~ /^deploy\/[^\/]+\.(sh|py)$/ && $1 !~ /^-rwx/ {print $NF}')"
[[ -z "$bad" ]] || { echo "deploy scripts lost their executable bit in git: $bad" >&2; exit 3; }

mkdir "$work/src" && tar -xzf "$out/source.tar.gz" -C "$work/src"
info="$(python3 "$HERE/schema_info.py" "$work/src")"
head="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["schema_head"])' "$info")"
compat="$(python3 -c 'import json,sys; print(",".join(json.loads(sys.argv[1])["rollback_compatible"]))' "$info")"

docker build -q -f "$work/src/docker/app.Dockerfile"          -t "internship-hunter-app:$sha"    "$work/src"
docker build -q -f "$work/src/docker/agent.Dockerfile"        -t "internship-hunter-agent:$sha"  "$work/src"
docker build -q -f "$work/src/docker/egress-proxy.Dockerfile" -t "internship-hunter-egress:$sha" "$work/src"
docker save "internship-hunter-app:$sha" "internship-hunter-agent:$sha" \
  "internship-hunter-egress:$sha" | gzip -n > "$out/images.tar.gz"

printf 'sha=%s\nsource_sha256=%s\nimages_sha256=%s\ncreated=%s\nschema_head=%s\nrollback_compatible=%s\n' \
  "$sha" \
  "$(sha256sum "$out/source.tar.gz" | cut -d' ' -f1)" \
  "$(sha256sum "$out/images.tar.gz" | cut -d' ' -f1)" \
  "$(date +%s)" "$head" "$compat" > "$out/manifest"
echo "artifacts in $out (schema_head=$head rollback_compatible=${compat:-none})"
