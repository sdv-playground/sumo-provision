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
    /// Register (or update) a device in the identity roster.
    Register {
        /// Stable device id (e.g. a VIN or rig name).
        id: String,
        /// Device model / type (e.g. `managed-cvc`).
        #[arg(long)]
        model: Option<String>,
        /// File with the device's public key / CSR.
        #[arg(long)]
        pubkey_file: Option<PathBuf>,
    },
    /// List the device roster.
    Devices,
    /// Show one device by id.
    Device {
        /// Device id.
        id: String,
    },
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
    /// Assemble the flash bundle (signed envelopes + payloads) for a device —
    /// dry by default: builds exactly what would be uploaded, does not flash.
    Flash {
        /// Desired state from a Tower 2 channel.
        #[arg(long)]
        channel: String,
        /// Device id in the Tower 1 roster (the envelope recipient).
        #[arg(long)]
        device: String,
        /// Tower 2 base URL.
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Tower 1 base URL.
        #[arg(long, env = "SUMO_CA_URL", default_value = "http://localhost:8080")]
        ca_url: String,
        /// Actually flash the rig over SOVD (destructive). Requires `--token`.
        /// Without it, the bundle is only assembled and reported (dry).
        #[arg(long)]
        execute: bool,
        /// SOVD bearer JWT (from `sovd-token-helper /mint`), required with
        /// `--execute`.
        #[arg(long, env = "SOVD_TOKEN")]
        token: Option<String>,
        /// Emit the bundle / result as JSON.
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
        CaCmd::Register {
            id,
            model,
            pubkey_file,
        } => {
            let pubkey = match pubkey_file {
                Some(p) => Some(std::fs::read_to_string(&p)?.trim().to_string()),
                None => None,
            };
            let dev = ca
                .register_device(&wire::RegisterDevice { id, model, pubkey })
                .await?;
            print_device(&dev);
        }
        CaCmd::Devices => {
            let devices = ca.list_devices().await?;
            if devices.is_empty() {
                println!("(no devices registered)");
            } else {
                for d in &devices {
                    println!(
                        "{:<20} {:<14} {}",
                        d.id,
                        d.model.as_deref().unwrap_or("-"),
                        d.status
                    );
                }
            }
        }
        CaCmd::Device { id } => {
            let dev = ca
                .get_device(&id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("device '{id}' not registered"))?;
            print_device(&dev);
        }
    }
    Ok(())
}

fn print_device(d: &wire::Device) {
    println!("id      {}", d.id);
    if let Some(m) = &d.model {
        println!("model   {m}");
    }
    println!("status  {}", d.status);
    println!("pubkey  {}", d.pubkey.as_deref().unwrap_or("(none)"));
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
        RigCmd::Flash {
            channel,
            device,
            hub_url,
            ca_url,
            execute,
            token,
            json,
        } => {
            if execute {
                let jwt = token.ok_or_else(|| {
                    anyhow::anyhow!(
                        "--execute requires --token <jwt> (from sovd-token-helper /mint)"
                    )
                })?;
                let result = orchestrator::flash_execute(
                    &args.url, &hub_url, &ca_url, &channel, &device, &jwt,
                )
                .await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    print_flash_result(&result);
                }
            } else {
                let bundle =
                    orchestrator::flash_bundle(&args.url, &hub_url, &ca_url, &channel, &device)
                        .await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&bundle)?);
                } else {
                    print_bundle(&bundle);
                }
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
    println!("(read-only plan; `rig flash` assembles the signed envelopes)");
}

fn print_bundle(b: &orchestrator::FlashBundle) {
    if b.components.is_empty() {
        println!("up to date — nothing to flash for channel '{}'", b.channel);
        return;
    }
    println!(
        "flash bundle for device '{}' (channel '{}'):",
        b.device, b.channel
    );
    let mut total = 0u64;
    for c in &b.components {
        println!(
            "  {} — signed envelope {}, {} payload(s):",
            c.entity,
            human_size(c.envelope_bytes as u64),
            c.payloads.len()
        );
        for p in &c.payloads {
            println!("    {:<14} {}  ({})", p.uri, p.outer, human_size(p.size));
            total += p.size;
        }
    }
    println!(
        "\n{} component(s), {} of payloads to upload",
        b.components.len(),
        human_size(total)
    );
    println!(
        "would flash (per component): SOVD open_update → upload manifest + payloads → prepare → execute → commit"
    );
    println!("(dry run — no rig flash; the live flash authenticates to SOVD with a sovd-token-helper JWT)");
}

fn print_flash_result(r: &orchestrator::FlashResult) {
    if r.components.is_empty() {
        println!("nothing flashed — up to date for channel '{}'", r.channel);
        return;
    }
    println!("flashed device '{}' (channel '{}'):", r.device, r.channel);
    for c in &r.components {
        println!("  {:<8} update {}  → {}", c.entity, c.update_id, c.status);
    }
    println!(
        "\nstaged. Issue the verdict (ECU reset when safe, then commit) to finalize, or roll back."
    );
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
