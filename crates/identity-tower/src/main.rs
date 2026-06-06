//! Tower 1 — Identity & Key Authority (`sumo-ca`).
//!
//! Owns device identity and key material; blind to software. Skeleton: serves
//! health/version only. The identity roster, keystore minting, and the
//! enrollment flow land against the roadmap in `architecture.md`.

use std::net::SocketAddr;

use axum::{routing::get, Json, Router};
use clap::Parser;
use serde::Serialize;

/// Tower 1 — the identity & key authority.
#[derive(Parser, Debug)]
#[command(name = "sumo-ca", version, about)]
struct Args {
    /// Address to bind the HTTP API to.
    #[arg(long, env = "SUMO_CA_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
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

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version));

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "sumo-ca (Tower 1 — identity) listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
