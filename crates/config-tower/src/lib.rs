//! Tower 3 — Configuration (`sumo-cfg`).
//!
//! Owns the parameter **schema** a model version declares and the **assignment**
//! each vehicle was given out of it, and validates the second against the first.
//! Schema-agnostic: a set's declaration is a JSON Schema (draft 2020-12) and the
//! tower knows nothing else about it — no fleet's parameter grammar is compiled
//! in here.
//!
//! Passive like the other two: nothing in this crate dials a rig. An assignment
//! is an intention recorded offboard; the orchestrator is what carries it to a
//! node, either as the canonical blob (`GET …/blob`) or as a Tower 2
//! `Part { kind: "param-blob" }` referencing that blob by hash.
//!
//! Uses its own database (default `sumo_cfg`) so its migrations stay independent
//! of Tower 1's and Tower 2's — the three towers can share one Postgres server,
//! different DBs.
//!
//! The router is a library so the API can be tested by calling it; the binary
//! (`src/main.rs`) is flags, a pool and `axum::serve` over exactly this router.

pub mod blob;

mod assignments;
mod error;
mod schemas;

use std::time::Duration;

use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub use error::AppError;

/// The database this tower answers out of, connected and migrated.
pub async fn open(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = connect_with_retry(database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("configuration store ready (postgres)");
    Ok(pool)
}

/// The whole surface, over one pool.
pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/schemas", get(schemas::list_schemas))
        .route("/schemas/{model}/{version}", get(schemas::get_schema))
        .route("/admin/schemas/{model}/{version}", put(schemas::put_schema))
        .route(
            "/vehicles/{vehicle_id}/assignments",
            get(assignments::list_assignments),
        )
        .route(
            "/vehicles/{vehicle_id}/assignments/{set_id}",
            get(assignments::get_assignment),
        )
        .route(
            "/vehicles/{vehicle_id}/assignments/{set_id}/blob",
            get(assignments::get_blob),
        )
        .route(
            "/admin/vehicles/{vehicle_id}/assignments/{set_id}",
            put(assignments::put_assignment).delete(assignments::delete_assignment),
        )
        .with_state(pool)
}

/// Connect to Postgres, retrying briefly so the tower tolerates the database
/// still warming up (e.g. right after `docker compose up`).
async fn connect_with_retry(url: &str) -> anyhow::Result<PgPool> {
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
        service: "sumo-cfg",
        version: env!("CARGO_PKG_VERSION"),
    })
}
