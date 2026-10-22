#!/usr/bin/env bash
# Install, without root, a checksummed Node 22 and the CLI versions PINNED in docker/agent.Dockerfile
# (read from it, so the probe can never drift from the image), into <dir>; prints <dir>/bin, which
# holds node, claude and codex for tests/cli_probe/run_probe.sh (HUNTER_CLI_BIN).
#   install.sh <dir>
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="$HERE/../../docker/agent.Dockerfile"
DIR="$(realpath -m "${1:?target directory}")"
NODE_VER=v22.23.4
NODE_SHA=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce
CC="$(sed -n 's/^ARG CLAUDE_CODE_VERSION=\([0-9.]*\)$/\1/p' "$DOCKERFILE")"
CX="$(sed -n 's/^ARG CODEX_VERSION=\([0-9.]*\)$/\1/p' "$DOCKERFILE")"
[[ -n "$CC" && -n "$CX" ]] || { echo "cannot read the pinned CLI versions from $DOCKERFILE" >&2; exit 1; }

mkdir -p "$DIR/bin"
tarball="$DIR/node-$NODE_VER-linux-x64.tar.xz"
if [[ ! -x "$DIR/node-$NODE_VER-linux-x64/bin/node" ]]; then
  curl -fsSL --retry 4 -o "$tarball" "https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-linux-x64.tar.xz"
  echo "$NODE_SHA  $tarball" | sha256sum -c - >/dev/null
  tar xJf "$tarball" -C "$DIR"
fi
export PATH="$DIR/node-$NODE_VER-linux-x64/bin:$PATH"
npm install --no-audit --no-fund --loglevel=error --prefix "$DIR/cli" \
  "@anthropic-ai/claude-code@$CC" "@openai/codex@$CX" >/dev/null
ln -sf "$DIR/node-$NODE_VER-linux-x64/bin/node" "$DIR/bin/node"
ln -sf "$DIR/cli/node_modules/.bin/claude" "$DIR/bin/claude"
ln -sf "$DIR/cli/node_modules/.bin/codex" "$DIR/bin/codex"
got_cc="$("$DIR/bin/claude" --version | awk '{print $1}')"
got_cx="$("$DIR/bin/codex" --version | awk '{print $NF}')"
[[ "$got_cc" == "$CC" && "$got_cx" == "$CX" ]] \
  || { echo "installed claude $got_cc / codex $got_cx, pinned $CC / $CX" >&2; exit 1; }
echo "$DIR/bin"
