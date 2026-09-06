# Container image for the sumo-provision towers — sumo-ca (Tower 1, identity),
# sumo-hub (Tower 2, software) and sumo-cfg (Tower 3, configuration). One image
# carries all three binaries; compose runs it three times with a different
# command. Multi-stage: cargo build on the pinned toolchain, then a slim runtime
# with just the binaries + a CA bundle.
#
#   docker build -t sumo-provision/towers .
#   docker run … sumo-provision/towers sumo-ca      # Tower 1
#   docker run … sumo-provision/towers sumo-hub     # Tower 2
#   docker run … sumo-provision/towers sumo-cfg     # Tower 3
#
# The towers are 12-factor: bind/DB/paths are env vars (SUMO_CA_BIND,
# SUMO_HUB_BIND, SUMO_CFG_BIND, DATABASE_URL, SUMO_HUB_BLOB_DIR, key paths). Key
# material auto-generates on first run under the key/data dirs, which compose
# mounts as named volumes so it persists across restarts. See compose.towers.yml.

# ---- builder ---------------------------------------------------------------
# Pinned to rust-toolchain.toml (1.96.0) so the image build can't drift from a
# host build. Bookworm so the runtime base (bookworm-slim) shares its glibc.
FROM rust:1.96-bookworm AS builder

WORKDIR /src

# Cargo git-deps are all public HTTPS (github / gitlab) — no SSH key needed. The
# base image already trusts public CAs, so `cargo fetch` over HTTPS just works.
# Copy the manifests + lockfile first so the dependency graph layer caches
# independently of source edits.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build only the three tower binaries (not the whole workspace: the cli pulls the
# SOVD flash engine + more, which the towers don't need).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p identity-tower -p software-tower -p config-tower \
    && mkdir -p /out \
    && cp target/release/sumo-ca target/release/sumo-hub target/release/sumo-cfg /out/

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: the towers make outbound TLS calls (e.g. sumo-hub is fetched
# from by clients; sumo-ca mints against the hub signer). libssl not needed —
# reqwest here is built with rustls in the consuming crates — but the CA bundle
# is cheap insurance for any HTTPS the binaries do.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/sumo-ca /usr/local/bin/sumo-ca
COPY --from=builder /out/sumo-hub /usr/local/bin/sumo-hub
COPY --from=builder /out/sumo-cfg /usr/local/bin/sumo-cfg

# Non-root. The data/key dirs are volume mount points; compose owns their
# ownership via the named volumes, and the binaries create files there at runtime.
RUN useradd --system --uid 10001 --create-home --home-dir /home/sumo sumo \
    && mkdir -p /data /keys \
    && chown -R sumo:sumo /data /keys
USER sumo
WORKDIR /home/sumo

# No ENTRYPOINT baked in: compose (or `docker run`) passes `sumo-ca` / `sumo-hub`
# / `sumo-cfg` as the command. All honour their SUMO_*_BIND / DATABASE_URL /
# key-path envs.
