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
    /// Show a channel's target state — its desired vehicle tree (Tower 2 only,
    /// no rig).
    Channel {
        /// Channel name (e.g. `bleeding`).
        name: String,
        /// Emit the tree as JSON.
        #[arg(long)]
        json: bool,
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
    /// Read the rig's observed state (the vehicle tree).
    State {
        /// Emit the tree as JSON (e.g. to capture a release).
        #[arg(long)]
        json: bool,
    },
    /// Diff the rig against a desired release — a tree JSON file or a Tower 2 channel.
    Diff {
        /// Desired tree from a JSON file `{ "entities": { … } }`.
        #[arg(long, conflicts_with = "channel")]
        release: Option<PathBuf>,
        /// Desired tree from a Tower 2 channel (e.g. `bleeding`).
        #[arg(long, required_unless_present = "release")]
        channel: Option<String>,
        /// Tower 2 base URL (used with `--channel`).
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Show the delta flash plan (ship vs reuse-from-active-bank) instead of
        /// the plain diff — i.e. the parts that must actually be shipped.
        #[arg(long)]
        plan: bool,
    },
    /// Plan how to bring the rig to a channel's desired state: the ship-set
    /// resolved against Tower 2 (read-only — does not flash).
    Apply {
        /// Desired state from a Tower 2 channel (e.g. `bleeding`).
        #[arg(long)]
        channel: String,
        /// Tower 2 base URL.
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Emit the plan as JSON.
        #[arg(long)]
        json: bool,
    },
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
        HubCmd::Channel { name, json } => {
            let tree = hub
                .channel_tree(&name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("channel '{name}' not found on {}", args.url))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tree)?);
            } else {
                print_tree(&tree);
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
        RigCmd::State { json } => {
            let observed = orchestrator::read_rig_state(&args.url).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&observed)?);
            } else {
                print_tree(&observed);
            }
        }
        RigCmd::Diff {
            release,
            channel,
            hub_url,
            plan,
        } => {
            let observed = orchestrator::read_rig_state(&args.url).await?;
            let desired = match (release, channel) {
                (Some(path), _) => serde_json::from_reader(std::fs::File::open(&path)?)?,
                (None, Some(name)) => SoftwareClient::new(&hub_url)
                    .channel_tree(&name)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("channel '{name}' not found on {hub_url}"))?,
                (None, None) => unreachable!("clap requires --release or --channel"),
            };
            if plan {
                print_plan(&wire::flash_plan(&observed, &desired));
            } else {
                print_diff(&wire::diff(&observed, &desired));
            }
        }
        RigCmd::Apply {
            channel,
            hub_url,
            json,
        } => {
            let plan = orchestrator::apply_plan(&args.url, &hub_url, &channel).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_apply(&plan);
            }
        }
    }
    Ok(())
}

fn print_tree(tree: &wire::Tree) {
    for (path, e) in &tree.entities {
        let ver = e
            .version
            .as_deref()
            .map(|v| format!(" — {v}"))
            .unwrap_or_default();
        println!("{path}  [{}]{ver}", e.kind);
        if e.parts.is_empty() {
            println!("    (no signed manifest)");
        }
        for p in &e.parts {
            println!("    {:<16} {}", p.id, p.content);
        }
    }
}

fn print_diff(d: &wire::TreeDiff) {
    if d.is_empty() {
        println!("up to date — nothing to flash");
        return;
    }
    for e in &d.entities_added {
        println!("+ entity {e}");
    }
    for e in &d.entities_removed {
        println!("- entity {e}");
    }
    for c in &d.parts {
        let sym = match c.change {
            wire::Change::Added => '+',
            wire::Change::Removed => '-',
            wire::Change::Changed => '~',
        };
        println!("{sym} {}  {} [{}]", c.entity, c.part, c.kind);
    }
}

fn print_plan(plan: &wire::FlashPlan) {
    if plan.is_noop() {
        println!("up to date — every part already in the active bank");
        return;
    }
    let (mut ship, mut reuse) = (0, 0);
    for p in &plan.parts {
        match p.plan {
            wire::PartPlan::Ship => {
                ship += 1;
                println!(
                    "↑ ship   {} {} [{}]  {}",
                    p.entity, p.part, p.kind, p.content
                );
            }
            wire::PartPlan::Reuse => reuse += 1,
        }
    }
    println!("\n{ship} to ship from Tower 2, {reuse} reused bank-to-bank on-device");
}

fn print_apply(plan: &orchestrator::ApplyPlan) {
    if plan.is_noop() {
        println!(
            "up to date — nothing to ship for channel '{}'",
            plan.channel
        );
        return;
    }
    for c in &plan.components {
        let ver = c
            .version
            .as_deref()
            .map(|v| format!(" {v}"))
            .unwrap_or_default();
        println!(
            "{}{}  — ship {}, reuse {}",
            c.entity,
            ver,
            c.ship.len(),
            c.reuse
        );
        for s in &c.ship {
            match &s.blob {
                Some(b) => println!("  ↑ {:<14} {}  ({})", s.part, s.content, human_size(b.size)),
                None => println!("  ✗ {:<14} {}  — NOT in Tower 2", s.part, s.content),
            }
        }
    }
    let missing = plan.missing();
    let ship_total: usize = plan.components.iter().map(|c| c.ship.len()).sum();
    print!(
        "\n{ship_total} part(s) to ship, {} total",
        human_size(plan.ship_bytes())
    );
    if missing.is_empty() {
        println!();
    } else {
        println!(" — {} unservable (not in Tower 2)", missing.len());
    }
    println!(
        "flash (per component): SOVD open_update → upload manifest + parts → prepare → execute → commit"
    );
    println!("(read-only plan; the live flash needs a UDS unlock via the security helper)");
}

/// Render a byte count as a short human string (e.g. `1.2 MB`).
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
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
