#!/usr/bin/env bash
# Local convenience: build + sign in one step. CI uses build-artifacts.sh and sign-bundle.sh
# in separate jobs so the signing key never meets repository code.
# Usage: deploy/make-bundle.sh <40-hex-sha> <ssh-signing-key> <out.tar>
set -Eeuo pipefail
sha="${1:?sha}"; key="${2:?signing key}"; out="${3:?output path}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
"$HERE/build-artifacts.sh" "$sha" "$work/a"
"$HERE/sign-bundle.sh" "$work/a" "$key" "$sha" "$out"
