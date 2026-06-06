#!/usr/bin/env bash
#
# install-deps.sh — install build & runtime dependencies for sumo-provision.
# Target: Ubuntu 24.04.
#
# Idempotent — safe to re-run. Installs:
#   - build tooling: build-essential, pkg-config, git, curl, ca-certificates
#   - shellcheck (lints the shell scripts)
#   - Docker + the Docker Compose v2 plugin (local stack: postgres, minio)
#   - the Rust toolchain via rustup, with rustfmt + clippy
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

if ! grep -qi 'ubuntu' /etc/os-release 2>/dev/null; then
    echo "warning: this script targets Ubuntu 24.04; your OS may differ." >&2
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=()
else
    SUDO=(sudo)
fi

# --- apt packages ----------------------------------------------------------
PKGS=(
    build-essential
    pkg-config
    git
    curl
    ca-certificates
    shellcheck
    docker-compose-v2
)
# Only install the Docker engine if none is present, so we don't clobber an
# existing docker-ce / docker.io installation.
if ! command -v docker >/dev/null 2>&1; then
    PKGS+=(docker.io)
fi

echo "==> Installing apt packages: ${PKGS[*]}"
"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y --no-install-recommends "${PKGS[@]}"

# --- docker group (use docker without sudo) --------------------------------
USERNAME="$(id -un)"
if [ "$USERNAME" != "root" ] && ! id -nG "$USERNAME" | grep -qw docker; then
    echo "==> Adding '$USERNAME' to the 'docker' group..."
    "${SUDO[@]}" usermod -aG docker "$USERNAME"
    REQUIRES_RELOGIN=1
fi

# --- Rust toolchain --------------------------------------------------------
if ! command -v rustup >/dev/null 2>&1; then
    echo "==> Installing the Rust toolchain via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi
echo "==> Ensuring rustfmt + clippy components..."
rustup component add rustfmt clippy >/dev/null

# --- summary ---------------------------------------------------------------
echo
echo "==> Done. Installed versions:"
rustc --version 2>/dev/null || true
cargo --version 2>/dev/null || true
docker --version 2>/dev/null || true
docker compose version 2>/dev/null || true

if [ "${REQUIRES_RELOGIN:-0}" -eq 1 ]; then
    echo
    echo "NOTE: you were added to the 'docker' group. Log out and back in"
    echo "      (or run 'newgrp docker') before using docker without sudo."
fi
