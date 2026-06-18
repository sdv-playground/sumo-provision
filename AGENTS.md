# sumo-provision Index

Rust lab-rig provisioning/update control plane with passive identity/software towers and an active orchestrator.

## Where to look

- `README.md` — dev/test scope, setup, local run, tower commands.
- `architecture.md` — living source of truth for towers, wire contracts, crypto and roadmap.
- `Cargo.toml` — workspace members.
- `crates/identity-tower/` — Tower 1 identity/key authority.
- `crates/software-tower/` — Tower 2 content/channel/signing service.
- `crates/orchestrator/` — dual-homed rig orchestration library.
- `crates/cli/` — `cargo run -p cli -- ...` command surface.
- `docker-compose.yml`, `start.sh` — local Postgres/MinIO/soft-HSM tower stack.

## Essential commands

No component-local `mise` file is present; use scripts and Cargo from this submodule root.

```bash
./install-deps.sh
./start.sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo run -p cli -- hub ping
cargo run -p cli -- hub publish FILE
```

Finding commands:

```bash
rg --files -g 'Cargo.toml' -g 'README*' -g 'architecture.md' -g 'docker-compose.yml' -g 'migrations/**'
rg -n "Tower 1|Tower 2|sumo-ca|sumo-hub|orchestrator|dev-only|production|channel|target release" README.md architecture.md crates docker-compose.yml
```

## Stack

- Rust 2021 services/CLI, Docker Compose, Postgres, S3-compatible object store, soft-HSM.

## Guardrails

- Development/test lab infrastructure only; do not position as production OTA/fleet management.
- Towers are passive; the orchestrator is the only component that talks to both tower and rig.
- Tower 1 stays identity/key-only; Tower 2 owns software/content/signing.

## Gotchas

- `./start.sh` owns local ports `8080` and `8081` plus backing services.
- Status is early development; architecture may be ahead of code.

## Missing docs/specs to watch

- Public/stable API guarantees are intentionally absent.
- Roadmap/open questions in `architecture.md` must be checked before expanding behavior.
