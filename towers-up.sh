#!/usr/bin/env bash
# towers-up.sh — bring the whole tower stack up in Docker (Tower 1 sumo-ca,
# Tower 2 sumo-hub, their two Postgres instances, minio). Unlike start.sh — which
# cargo-builds the towers and runs them as host processes against a shared
# postgres — this runs EVERYTHING in containers. Nothing on the host but Docker.
#
#   ./towers-up.sh            # build (if needed) + up; waits until both healthy
#   ./towers-up.sh --build    # force a rebuild of the tower image first
#   ./towers-up.sh --down     # stop the stack (keeps data volumes)
#   ./towers-up.sh --wipe     # stop + delete all state (DBs, keys, blobs)
#
# Ports: sumo-ca :8080, sumo-hub :8081, minio :9000/:9001.
set -euo pipefail
cd "$(dirname "$0")" || exit 1

COMPOSE=(docker compose -f compose.towers.yml)

case "${1:-}" in
  --down) exec "${COMPOSE[@]}" down ;;
  --wipe) exec "${COMPOSE[@]}" down -v ;;
esac

BUILD_FLAG=()
[ "${1:-}" = "--build" ] && BUILD_FLAG=(--build)

# --force-recreate: a prior aborted `up` (e.g. a port clash on another service)
# can leave a tower container created but detached from the network — it then
# fails DNS ("Temporary failure in name resolution") on every restart. Recreating
# guarantees each container is freshly attached to the compose network.
echo "==> Starting the tower stack in Docker ..."
"${COMPOSE[@]}" up -d --force-recreate "${BUILD_FLAG[@]}"

echo "==> Waiting for both towers to answer /healthz ..."
ok_ca=0 ok_hub=0
for _ in $(seq 1 60); do
  [ "$ok_ca" -eq 0 ] && curl -sf -o /dev/null http://localhost:8080/healthz 2>/dev/null && { ok_ca=1; echo "    Tower 1 (sumo-ca)  :8080 healthy"; }
  [ "$ok_hub" -eq 0 ] && curl -sf -o /dev/null http://localhost:8081/healthz 2>/dev/null && { ok_hub=1; echo "    Tower 2 (sumo-hub) :8081 healthy"; }
  [ "$ok_ca" -eq 1 ] && [ "$ok_hub" -eq 1 ] && break
  sleep 1
done

if [ "$ok_ca" -ne 1 ] || [ "$ok_hub" -ne 1 ]; then
  echo "==> ERROR: a tower did not come up. Recent logs:" >&2
  "${COMPOSE[@]}" logs --tail 30 sumo-ca sumo-hub >&2
  exit 1
fi

echo "==> Tower stack up:  sumo-ca :8080   sumo-hub :8081   minio :9000/:9001"
echo "    Stop with ./towers-up.sh --down  (or --wipe to also delete state)."
echo "    Note: the workshop minter (sovd-token-helper) is NOT in this stack — it"
echo "    needs a Tower-1 delegate cert at startup; use tower-provision/up.sh for it."
