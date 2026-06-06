# sumo-provision

Control plane for provisioning and updating **development / test rigs** that run
the sumo stack. Two passive "towers" plus an active orchestrator turn rig bring-up
and software updates into a button-press, instead of hand-run per-rig scripts.

> **⚠ Development / test only.** This is lab infrastructure — not a production
> OTA or fleet-management system, and not for managing real vehicles. See
> [`architecture.md`](architecture.md) for why the dev-only scope is load-bearing.

## What's inside

- **Tower 1 — Identity & Key Authority** (`sumo-ca`): device identity and key
  material. Blind to software.
- **Tower 2 — Software & Signing** (`sumo-hub`): content store, channels, the
  digital twin, and the software signing key.
- **Orchestrator**: the only component that talks to both a tower and a rig —
  reports rig state, asks for an update, and flashes over SOVD.

Neither tower ever connects to a rig; the orchestrator is the single dual-homed
component. The full rationale, wire contracts, and crypto model are in
[`architecture.md`](architecture.md) — the living source of truth for this repo.

## Status

Early development. Nothing here is stable yet. The architecture is documented
first ([`architecture.md`](architecture.md)); code lands against the roadmap in
that document.

## Stack

Rust · Docker (`docker-compose` for local bring-up) · Postgres (metadata) ·
S3-compatible object store (blobs) · soft-HSM (keys).

## Setup (Ubuntu 24.04)

```sh
./install-deps.sh
```

Installs the Rust toolchain, Docker + the Compose v2 plugin, and shellcheck.
Idempotent — safe to re-run.

## Run it locally

```sh
./start.sh
```

Builds and starts both towers (`sumo-ca` on `:8080`, `sumo-hub` on `:8081`) plus
the backing services (postgres, minio), then waits. Press Ctrl-C to shut
everything down cleanly. Probe a tower with:

```sh
cargo run -p cli -- hub ping            # Tower 2 health/version
cargo run -p cli -- hub publish FILE    # publish an artifact
```

## License

To be decided before this repository is made public.
