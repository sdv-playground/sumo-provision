//! `sumo-provision` — tester / operator CLI for the provisioning towers.
//!
//! `hub` drives Tower 2 (software): publish artifacts, fetch blobs. `ca` drives
//! Tower 1 (identity): health today, enrollment as Tower 1 grows. Both build on
//! the reusable `client` library, so anything embedding the towers shares the
//! same access layer.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use client::{IdentityClient, SoftwareClient, TowerClient};
use wire::ContentHash;

#[derive(Parser, Debug)]
#[command(name = "sumo-provision", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Talk to Tower 2 (software): publish artifacts, fetch blobs.
    Hub(HubArgs),
    /// Talk to Tower 1 (identity).
    Ca(CaArgs),
    /// Talk to a rig over SOVD.
    Rig(RigArgs),
}

#[derive(Args, Debug)]
struct HubArgs {
    /// Base URL of Tower 2.
    #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
    url: String,
    #[command(subcommand)]
    cmd: HubCmd,
}

#[derive(Subcommand, Debug)]
enum HubCmd {
    /// Probe health + version.
    Ping,
    /// Publish a file as an artifact (encrypt-once, content-addressed).
    Publish {
        /// File to publish.
        file: PathBuf,
    },
    /// Fetch a blob by its outer hash.
    Get {
        /// The outer hash (`sha256:…`).
        hash: String,
        /// Write to this file instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
struct CaArgs {
    /// Base URL of Tower 1.
    #[arg(long, env = "SUMO_CA_URL", default_value = "http://localhost:8080")]
    url: String,
    #[command(subcommand)]
    cmd: CaCmd,
}

#[derive(Subcommand, Debug)]
enum CaCmd {
    /// Probe health + version.
    Ping,
}

#[derive(Args, Debug)]
struct RigArgs {
    /// Base URL of the rig's SOVD endpoint.
    #[arg(long, env = "SUMO_RIG_URL", default_value = "http://localhost:4000")]
    url: String,
    #[command(subcommand)]
    cmd: RigCmd,
}

#[derive(Subcommand, Debug)]
enum RigCmd {
    /// Read the rig's observed state (components + versions).
    State,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Hub(args) => run_hub(args).await,
        Command::Ca(args) => run_ca(args).await,
        Command::Rig(args) => run_rig(args).await,
    }
}

async fn run_hub(args: HubArgs) -> anyhow::Result<()> {
    let hub = SoftwareClient::new(&args.url);
    match args.cmd {
        HubCmd::Ping => ping(hub.tower(), &args.url).await?,
        HubCmd::Publish { file } => {
            let bytes = std::fs::read(&file)?;
            let aref = hub.publish_artifact(&bytes).await?;
            println!("inner {}", aref.inner);
            println!("outer {}", aref.outer);
            println!("size  {}", aref.size);
        }
        HubCmd::Get { hash, out } => {
            let outer: ContentHash = hash
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid hash: {hash}"))?;
            let bytes = hub
                .get_blob(&outer)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no blob {outer}"))?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &bytes)?;
                    eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
                }
                None => std::io::stdout().write_all(&bytes)?,
            }
        }
    }
    Ok(())
}

async fn run_ca(args: CaArgs) -> anyhow::Result<()> {
    let ca = IdentityClient::new(&args.url);
    match args.cmd {
        CaCmd::Ping => ping(ca.tower(), &args.url).await?,
    }
    Ok(())
}

async fn run_rig(args: RigArgs) -> anyhow::Result<()> {
    match args.cmd {
        RigCmd::State => {
            let state = orchestrator::read_rig_state(&args.url).await?;
            for c in &state.components {
                println!("{}  [{}]  {}", c.id, c.kind, c.name);
                match &c.installed {
                    Some(m) => {
                        let ver = format!("{} {}", m.identity.name, m.identity.version);
                        println!("    version  {}", ver.trim());
                        for f in &m.files {
                            println!("    {:<16} {}", f.path, f.sha256);
                        }
                    }
                    None => println!("    (no signed manifest — never flashed)"),
                }
            }
        }
    }
    Ok(())
}

async fn ping(tower: &TowerClient, url: &str) -> anyhow::Result<()> {
    let healthy = tower.healthy().await?;
    let v = tower.version().await?;
    println!(
        "{url} — {} v{} ({})",
        v.service,
        v.version,
        if healthy { "healthy" } else { "unhealthy" }
    );
    Ok(())
}
