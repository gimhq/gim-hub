#!/usr/bin/env bash
# Build the gim-hub image and verify the binary was built from this checkout.
#
# Usage: scripts/docker-build.sh IMAGE
#
# The checkout's revision (HEAD, plus a hash of uncommitted changes to tracked
# files) is passed as GIM_HUB_BUILD_REV and must match `gim-hub version` in the
# built image, so a stale binary fails the build instead of passing unnoticed.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE="${1:?usage: docker-build.sh IMAGE}"

rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ "$rev" != "unknown" && -n "$(git status --porcelain --untracked-files=no)" ]]; then
    rev="$rev-dirty-$(git diff HEAD | sha256sum | cut -c1-12)"
fi

docker build --label ai-agent=true --build-arg GIM_HUB_BUILD_REV="$rev" -t "$IMAGE" .

want="gim-hub $(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1) ($rev)"
got="$(docker run --rm --label ai-agent=true --entrypoint gim-hub "$IMAGE" version)"
if [[ "$got" != "$want" ]]; then
    echo "docker-build: FAIL: stale binary in $IMAGE: got '$got', want '$want'" >&2
    exit 1
fi
echo "docker-build: ok   $got"
