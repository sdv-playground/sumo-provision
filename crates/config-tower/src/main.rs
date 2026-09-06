//! Tower 3 — Configuration (`sumo-cfg`).
//!
//! Flags, a pool, the router, a listener and a shutdown — the same five things
//! and in the same order as Tower 1 and Tower 2. Everything it serves is
//! [`config_tower`].

use std::net::SocketAddr;

use clap::Parser;

/// Tower 3 — the configuration tower.
#[derive(Parser, Debug)]
#[command(name = "sumo-cfg", version, about)]
struct Args {
    /// Address to bind the HTTP API to.
    #[arg(long, env = "SUMO_CFG_BIND", default_value = "0.0.0.0:8082")]
    bind: SocketAddr,

    /// PostgreSQL connection string for the configuration store (its own DB,
    /// distinct from Tower 1's and Tower 2's).
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://sumo:dev-only-not-secret@localhost:5432/sumo_cfg"
    )]
    database_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();

    let pool = config_tower::open(&args.database_url).await?;
    let app = config_tower::router(pool);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "sumo-cfg (Tower 3 — configuration) listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
