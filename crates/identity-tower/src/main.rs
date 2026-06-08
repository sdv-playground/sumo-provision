//! Tower 1 — Identity & Key Authority (`sumo-ca`).
//!
//! Owns device identity and key material; blind to software. Serves the device
//! identity roster (register + read). Keystore minting and the CSR enrollment
//! flow land against the roadmap in `architecture.md`.
//!
//! Uses its own database (default `sumo_ca`) so its migrations stay independent
//! of Tower 2's — the two towers can share one Postgres server, different DBs.

mod ca;
mod devices;
mod keystore;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;

use crate::devices::AppState;

/// Tower 1 — the identity & key authority.
#[derive(Parser, Debug)]
#[command(name = "sumo-ca", version, about)]
struct Args {
    /// Address to bind the HTTP API to.
    #[arg(long, env = "SUMO_CA_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// PostgreSQL connection string for the device roster (its own DB, distinct
    /// from Tower 2's).
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://sumo:dev-only-not-secret@localhost:5432/sumo_ca"
    )]
    database_url: String,

    /// CA signing key (PKCS#8 DER, P-256). Generated on first run.
    #[arg(long, env = "SUMO_CA_KEY", default_value = "data/ca-authority.key")]
    ca_key: PathBuf,

    /// CA root certificate (X.509 DER). Self-signed on first run.
    #[arg(long, env = "SUMO_CA_CERT", default_value = "data/ca-cert.der")]
    ca_cert: PathBuf,
}

#[derive(Serialize)]
struct Version {
    service: &'static str,
    version: &'static str,
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<Version> {
    Json(Version {
        service: "sumo-ca",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();

    let pool = connect_with_retry(&args.database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("device roster ready (postgres)");

    let ca = Arc::new(load_or_generate_ca(&args.ca_key, &args.ca_cert)?);
    let state = AppState { pool, ca };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/admin/devices", post(devices::register_device))
        .route("/admin/devices/{id}/enroll", post(devices::enroll_device))
        .route(
            "/admin/devices/{id}/keystore",
            post(keystore::mint_keystore_endpoint),
        )
        .route("/admin/ca/cert", get(devices::ca_cert))
        .route("/devices", get(devices::list_devices))
        .route("/devices/{id}", get(devices::get_device))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "sumo-ca (Tower 1 — identity) listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Connect to Postgres, retrying briefly so the tower tolerates the database
/// still warming up (e.g. right after `docker compose up`).
async fn connect_with_retry(url: &str) -> anyhow::Result<sqlx::PgPool> {
    let mut last_err = None;
    for attempt in 1..=15 {
        match PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(3))
            .connect(url)
            .await
        {
            Ok(pool) => return Ok(pool),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "postgres not ready yet, retrying...");
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Err(anyhow::anyhow!(
        "could not connect to postgres at {url}: {}",
        last_err.expect("loop ran at least once")
    ))
}

/// Load the device CA from disk, or generate + persist it on first run (mirrors
/// Tower 2's signer bootstrap). The CA private key is crypto-critical — kept in
/// the gitignored `data/` dir at `0600`.
fn load_or_generate_ca(key: &Path, cert: &Path) -> anyhow::Result<ca::Ca> {
    if key.exists() && cert.exists() {
        ca::Ca::load(key, cert)
    } else {
        let authority = ca::Ca::generate()?;
        authority.save(key, cert)?;
        tracing::info!(key = %key.display(), cert = %cert.display(), "generated device CA root");
        Ok(authority)
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
