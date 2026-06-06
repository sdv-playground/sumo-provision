#!/usr/bin/env bash
#
# start.sh — run the sumo-provision stack locally, tear it down on Ctrl-C.
#
# Builds and starts both towers (sumo-ca on :8080, sumo-hub on :8081) plus the
# backing services (postgres, minio) via docker compose, then waits. Press
# Ctrl-C to shut everything down cleanly.
set -euo pipefail

cd "$(dirname "$0")" || exit 1

TOWER_PIDS=()
COMPOSE=()
INFRA_UP=0

cleanup() {
    echo
    echo "==> Shutting down the stack..."
    # The towers shut down gracefully on SIGINT.
    for pid in "${TOWER_PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
    done
    for pid in "${TOWER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    if [ "$INFRA_UP" -eq 1 ]; then
        "${COMPOSE[@]}" down || true
    fi
    echo "==> Stack stopped."
}
trap cleanup EXIT
trap 'exit 0' INT TERM

# 1. Build first — a compile error shouldn't spin anything up.
echo "==> Building towers..."
cargo build

# 2. Backing services. Detect Docker Compose v2 (plugin) or v1 (standalone);
#    skip gracefully if neither is present (the towers don't need them yet).
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
fi

if [ "${#COMPOSE[@]}" -gt 0 ]; then
    # Run the containers as the host user so data bind-mounted under ./data is
    # host-owned, never root-owned. Pre-create the dirs too: a missing bind-mount
    # source would otherwise be created by the daemon as root.
    export DOCKER_UID="$(id -u)"
    export DOCKER_GID="$(id -g)"
    mkdir -p data/postgres data/minio
    echo "==> Starting backing services (postgres, minio) via '${COMPOSE[*]}'..."
    if "${COMPOSE[@]}" up -d; then
        INFRA_UP=1
    else
        echo "    failed to start backing services — continuing with towers only."
    fi
else
    echo "==> Docker Compose not found — continuing with towers only."
    echo "    (install the compose plugin for postgres + minio; the towers don't"
    echo "     need them yet)"
fi

# 3. Towers.
echo "==> Starting sumo-ca (Tower 1, :8080) and sumo-hub (Tower 2, :8081)..."
./target/debug/sumo-ca &
TOWER_PIDS+=("$!")
./target/debug/sumo-hub &
TOWER_PIDS+=("$!")

echo "==> Stack is up. Press Ctrl-C to stop."

# 4. Block until Ctrl-C (or a tower exits on its own).
wait
