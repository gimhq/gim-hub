#!/usr/bin/env bash
# Admin UI gates, run in a pinned bun container (override with ADMIN_UI_IMAGE).
#
#   install  bun install --frozen-lockfile
#   check    install, lint, typecheck, test (with coverage), build
#   build    install, build (writes admin-ui/dist)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

case "${1:-}" in
    install) CMDS='bun install --frozen-lockfile' ;;
    check) CMDS='bun install --frozen-lockfile && bun run lint && bun run typecheck && bun run test && bun run build' ;;
    build) CMDS='bun install --frozen-lockfile && bun run build' ;;
    *)
        echo "usage: $0 {install|check|build}" >&2
        exit 2
        ;;
esac

IMAGE="${ADMIN_UI_IMAGE:-oven/bun:1.4.3}"
mkdir -p /srv/.tmp/cache/bun

docker run --rm --label ai-agent=true --name "ai-agent-gim-hub-admin-ui-$$" \
    -v "$PWD:$PWD" -w "$PWD/admin-ui" \
    -v /srv/.tmp/cache/bun:/cache/bun -e BUN_INSTALL_CACHE_DIR=/cache/bun \
    "$IMAGE" sh -c "$CMDS"
