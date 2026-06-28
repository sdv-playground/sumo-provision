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
    DOCKER_UID="$(id -u)"; export DOCKER_UID
    DOCKER_GID="$(id -g)"; export DOCKER_GID
    mkdir -p data/postgres data/minio
    # Only OWN the teardown for infra THIS instance starts. If another stack
    # instance already has the containers up, a second one must NOT `down` them on
    # exit — that terminates the live tower DBs out from under the first. (A killed
    # second instance's cleanup running `down` is exactly the "terminating
    # connection due to administrator command" → CA pool-timeout failure.)
    already_running=0
    if [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then already_running=1; fi
    echo "==> Starting backing services (postgres, minio) via '${COMPOSE[*]}'..."
    if "${COMPOSE[@]}" up -d; then
        if [ "$already_running" -eq 1 ]; then
            echo "    backing services were already up — NOT tearing them down on exit."
        else
            INFRA_UP=1
        fi
        # Persistence step: each tower uses its OWN database (separate fault
        # domains — a Tower 2 compromise must not read Tower 1's identity data).
        # Idempotent: create only if missing, so existing data dirs are fine too.
        echo "==> Waiting for postgres, then ensuring tower databases..."
        for _ in $(seq 1 30); do
            "${COMPOSE[@]}" exec -T postgres pg_isready -U sumo >/dev/null 2>&1 && break
            sleep 1
        done
        # Each tower uses its OWN database (separate fault domains). createdb is
        # the idempotent step: it creates the db, or reports it already exists.
        # Either branch continues — a re-run never aborts the stack.
        for db in sumo_hub sumo_ca; do
            if "${COMPOSE[@]}" exec -T postgres createdb -U sumo "$db" 2>/dev/null; then
                echo "    created $db"
            else
                echo "    $db already present"
            fi
        done
    else
        echo "    failed to start backing services — continuing without them."
    fi
else
    echo "==> Docker Compose not found — install the compose plugin for postgres"
    echo "    + minio (both towers need their Postgres databases to start)."
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
