//! Tower 2 — Software & Signing (`sumo-hub`).
//!
//! Owns content, channels, the digital twin, and the software signing key.
//! Step 1 (content core): encrypt-once publish + content-addressed blob fetch.
//! Channels, the twin, diff dispatch, and the per-node signer land against the
//! roadmap in `architecture.md`.

mod content;
mod crypto;
mod releases;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post, put};
use axum::{Json, Router};
use clap::Parser;
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;

use crate::content::AppState;
use crate::store::{FsBlobStore, PgIndex};

/// Tower 2 — the software & signing tower.
#[derive(Parser, Debug)]
#[command(name = "sumo-hub", version, about)]
struct Args {
    /// Address to bind the HTTP API to.
    #[arg(long, env = "SUMO_HUB_BIND", default_value = "0.0.0.0:8081")]
    bind: SocketAddr,

    /// PostgreSQL connection string for the artifact index.
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://sumo:dev-only-not-secret@localhost:5432/postgres"
    )]
    database_url: String,

    /// Directory for the content-addressed blob store.
    #[arg(long, env = "SUMO_HUB_BLOB_DIR", default_value = "data/blobs")]
    blob_dir: PathBuf,
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
        service: "sumo-hub",
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
    tracing::info!("artifact index ready (postgres)");

    let state = AppState {
        blobs: Arc::new(FsBlobStore::new(&args.blob_dir)),
        index: Arc::new(PgIndex::new(pool.clone())),
        pool: Some(pool),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/admin/artifacts", post(content::publish))
        .route("/admin/artifacts/{inner}", get(releases::artifact_exists))
        .route(
            "/admin/component-releases",
            post(releases::create_component_release),
        )
        .route(
            "/admin/campaign-releases",
            post(releases::create_campaign_release),
        )
        .route("/admin/channels/{name}", put(releases::set_channel))
        .route("/channels/{name}/tree", get(releases::channel_tree))
        .route("/blobs/{outer}", get(content::get_blob))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "sumo-hub (Tower 2 — software) listening");
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
