#!/usr/bin/env bash
# Run the project checks: fmt, clippy, test.
#
# By default the checks run in a rust container (override the image with
# CHECK_IMAGE). Pass --in-container or set GIM_HUB_CHECK_NATIVE=1 to run the
# cargo commands directly (used by CI).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CMDS='cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked'

if [[ "${1:-}" == "--in-container" || "${GIM_HUB_CHECK_NATIVE:-}" == "1" ]]; then
    exec bash -c "$CMDS"
fi

IMAGE="${CHECK_IMAGE:-rust:1.99-bookworm}"
mkdir -p /srv/.tmp/cache/cargo

docker run --rm --label ai-agent=true --name "ai-agent-gim-hub-check-$$" \
    -v "$PWD:$PWD" -w "$PWD" \
    -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR="$PWD/target" \
    "$IMAGE" bash -c "rustup component add rustfmt clippy >/dev/null 2>&1 || true; $CMDS"
