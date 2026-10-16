#!/usr/bin/env bash
# Build an image and verify the binary was built from this checkout.
#
# Usage: scripts/docker-build.sh IMAGE [hub|push-mock]
#
# TARGET `hub` (default) builds Dockerfile (gim-hub); `push-mock` builds
# Dockerfile.push-mock (gim-push-mock, docs/push-mock.md).
#
# The checkout's revision (HEAD, plus a hash of uncommitted changes to tracked
# files) is passed as GIM_HUB_BUILD_REV and must match `<binary> version` in the
# built image, so a stale binary fails the build instead of passing unnoticed.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE="${1:?usage: docker-build.sh IMAGE [hub|push-mock]}"
case "${2:-hub}" in
hub) DOCKERFILE=Dockerfile BIN=gim-hub ;;
push-mock) DOCKERFILE=Dockerfile.push-mock BIN=gim-push-mock ;;
*)
    echo "docker-build: unknown target '$2' (hub, push-mock)" >&2
    exit 2
    ;;
esac

rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ "$rev" != "unknown" && -n "$(git status --porcelain --untracked-files=no)" ]]; then
    rev="$rev-dirty-$(git diff HEAD | sha256sum | cut -c1-12)"
fi

docker build --label ai-agent=true --build-arg GIM_HUB_BUILD_REV="$rev" -f "$DOCKERFILE" -t "$IMAGE" .

want="$BIN $(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1) ($rev)"
got="$(docker run --rm --label ai-agent=true --entrypoint "$BIN" "$IMAGE" version)"
if [[ "$got" != "$want" ]]; then
    echo "docker-build: FAIL: stale binary in $IMAGE: got '$got', want '$want'" >&2
    exit 1
fi
echo "docker-build: ok   $got"
