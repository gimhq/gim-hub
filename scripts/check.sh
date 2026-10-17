#!/usr/bin/env bash
# Run the project checks: admin UI gates (scripts/admin-ui.sh check), then
# fmt, clippy, test. The UI gates come first: their build writes
# admin-ui/dist, which gim-hub-admin embeds and needs to compile.
#
# By default the checks run in containers (override the rust image with
# CHECK_IMAGE). Pass --in-container or set GIM_HUB_CHECK_NATIVE=1 to run only the
# cargo commands directly (used by CI).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CMDS='cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked'

if [[ "${1:-}" == "--in-container" || "${GIM_HUB_CHECK_NATIVE:-}" == "1" ]]; then
    exec bash -c "$CMDS"
fi

bash scripts/admin-ui.sh check

IMAGE="${CHECK_IMAGE:-rust:1.99-bookworm}"
mkdir -p /srv/.tmp/cache/cargo

docker run --rm --label ai-agent=true --name "ai-agent-gim-hub-check-$$" \
    -v "$PWD:$PWD" -w "$PWD" \
    -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR="$PWD/target" \
    "$IMAGE" bash -c "rustup component add rustfmt clippy >/dev/null 2>&1 || true; $CMDS"
