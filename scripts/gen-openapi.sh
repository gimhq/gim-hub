#!/usr/bin/env bash
# Regenerate openapi.json (client API v2 contract) from the utoipa annotations
# in crates/gim-hub-api.
#
# Runs in a rust container like scripts/check.sh (override the image with
# CHECK_IMAGE). Pass --in-container or set GIM_HUB_CHECK_NATIVE=1 to run cargo
# directly.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CMD='cargo run --locked -q -p gim-hub-api --example gen-openapi'

if [[ "${1:-}" == "--in-container" || "${GIM_HUB_CHECK_NATIVE:-}" == "1" ]]; then
    exec bash -c "$CMD"
fi

IMAGE="${CHECK_IMAGE:-rust:1.99-bookworm}"
mkdir -p /srv/.tmp/cache/cargo

docker run --rm --label ai-agent=true --name "ai-agent-gim-hub-gen-openapi-$$" \
    -v "$PWD:$PWD" -w "$PWD" \
    -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR="$PWD/target" \
    "$IMAGE" bash -c "$CMD"
