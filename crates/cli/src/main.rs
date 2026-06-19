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
        /// Narrow to this target type when the channel serves several.
        #[arg(long)]
        target_type: Option<String>,
        /// Narrow to this profile when the channel serves several.
        #[arg(long)]
        profile: Option<String>,
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
    /// Enroll one of a registered device's key slots: submit its CSR (DER
    /// PKCS#10). `device-decrypt` records the pubkey (no cert); a cert-bearing
    /// slot (`tls-identity`, …) gets a leaf back, stored in Tower 1.
    Enroll {
        /// Device id (register it first).
        id: String,
        /// Which key slot the CSR is for.
        #[arg(long, default_value = "device-decrypt")]
        key_id: String,
        /// CSR file for that slot (DER PKCS#10) — e.g. captured from the rig's
        /// `…/operations/x-sumo-csr/executions`.
        #[arg(long)]
        csr: PathBuf,
        /// Write the issued certificate PEM here (default: stdout). Ignored for
        /// `device-decrypt` (no cert).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Mint a device's HSM trust-anchor keystore SUIT (sw-authority = Tower 2's
    /// signer). Install it on the rig with `rig install-keystore`.
    MintKeystore {
        /// Device id (register + enroll it first, so it has a pubkey).
        id: String,
        /// Tower 2 base URL — to fetch the sw-authority signer pubkey.
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Write the keystore SUIT here (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fetch the identity-root CA certificate (PEM) — the fleet trust anchor a
    /// node pins to verify a peer's `tls-identity` leaf. Ship it in the policy
    /// partition's `roots/` as `device-identity-root.pem`.
    CaCert {
        /// Write the PEM here (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
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
        /// Narrow `--channel` to this target type when it serves several.
        #[arg(long, conflicts_with = "release")]
        target_type: Option<String>,
        /// Narrow `--channel` to this profile when it serves several.
        #[arg(long, conflicts_with = "release")]
        profile: Option<String>,
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
        #[command(flatten)]
        sel: ChannelSel,
        /// Tower 2 base URL.
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Emit the plan as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Assemble the flash bundle (signed envelopes + payloads) for a device —
    /// dry by default; `--execute` flashes the rig over SOVD (destructive).
    Flash {
        #[command(flatten)]
        sel: ChannelSel,
        /// Tower 2 base URL.
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Tower 1 base URL.
        #[arg(long, env = "SUMO_CA_URL", default_value = "http://localhost:8080")]
        ca_url: String,
        #[command(flatten)]
        auth: AuthArgs,
        /// Flash only this component (e.g. `rt`) — for a singleshot component that
        /// must flash in its own transaction (the no-mix guard). Omit for all.
        #[arg(long)]
        only: Option<String>,
        /// Actually flash the rig over SOVD (destructive). Without it, dry.
        #[arg(long)]
        execute: bool,
        /// Emit the bundle / result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Plan + run the campaign to bring the rig to a channel's target state:
    /// groups the ship-set by update-mode into ordered transactions (each
    /// singleshot component its own step, then the banked group), reports the
    /// plan, and with `--execute` runs the steps in order.
    Campaign {
        #[command(flatten)]
        sel: ChannelSel,
        /// Tower 2 base URL.
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        /// Tower 1 base URL.
        #[arg(long, env = "SUMO_CA_URL", default_value = "http://localhost:8080")]
        ca_url: String,
        #[command(flatten)]
        auth: AuthArgs,
        /// Actually run the campaign (destructive). Without it, just report the plan.
        #[arg(long)]
        execute: bool,
        /// Leave each banked step in trial instead of auto-committing it once the
        /// system is healthy — for a manual verdict (`./commit.sh` / `rig commit`).
        #[arg(long)]
        no_commit: bool,
    },
    /// Commit a staged update once its trial boot is healthy.
    Commit {
        /// Component to commit (e.g. `vm1`).
        #[arg(long)]
        component: String,
        /// The update id returned by `rig flash --execute`.
        #[arg(long)]
        update: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Roll a staged update back.
    Rollback {
        /// Component to roll back.
        #[arg(long)]
        component: String,
        /// The update id returned by `rig flash --execute`.
        #[arg(long)]
        update: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Commit the whole node's in-trial set in ONE verdict — the update session
    /// is the commit unit, never a single component. Use this after a
    /// node-reboot update (banked VMs): the device commits every component
    /// currently in trial, resolved from NV (no per-component update id needed).
    CommitTrials {
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Roll the whole node's in-trial set back in ONE verdict — see `commit-trials`.
    RollbackTrials {
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Reset a component so it boots its staged (trial) bank. `rig flash` already
    /// resets after staging; use this to re-issue the reboot for a staged update.
    Reset {
        /// Component to reset.
        #[arg(long)]
        component: String,
        /// The update id returned by `rig flash --execute`.
        #[arg(long)]
        update: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Install a minted HSM trust-anchor keystore SUIT on the rig — the device
    /// bootstrap; flash this before firmware on a factory-reset rig.
    InstallKeystore {
        /// The keystore SUIT file (from `ca mint-keystore`).
        #[arg(long)]
        suit: PathBuf,
        /// Tower 2 base URL — for the firmware signer pubkey (the validator anchor).
        #[arg(long, env = "SUMO_HUB_URL", default_value = "http://localhost:8081")]
        hub_url: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
}

/// A channel-target selector for the rig commands: the channel, plus the
/// optional `(target_type, profile)` narrowing for a channel that serves several
/// targets (the multi-profile selector — Tower 2 migration `0005`). Omit both to
/// resolve the channel's single target.
#[derive(Args, Debug)]
struct ChannelSel {
    /// Desired state from a Tower 2 channel (e.g. `bleeding`).
    #[arg(long)]
    channel: String,
    /// Narrow to this target type when the channel serves several (e.g.
    /// `managed-cvc`).
    #[arg(long)]
    target_type: Option<String>,
    /// Narrow to this profile when the channel serves several (e.g. `autosd`).
    #[arg(long)]
    profile: Option<String>,
}

impl ChannelSel {
    fn target(&self) -> orchestrator::ChannelTarget {
        orchestrator::ChannelTarget {
            channel: self.channel.clone(),
            target_type: self.target_type.clone(),
            profile: self.profile.clone(),
        }
    }
}

/// Auth for the SOVD flash wire: a device id (the token `aud` + envelope
/// recipient) and either a bearer JWT or minter creds to mint one.
#[derive(Args, Debug)]
struct AuthArgs {
    /// Device id in the Tower 1 roster (envelope recipient + token aud).
    #[arg(long)]
    device: String,
    /// SOVD bearer JWT (skip minting).
    #[arg(long, env = "SOVD_TOKEN")]
    token: Option<String>,
    /// `sovd-token-helper` base URL — mint a JWT when `--token` is absent.
    #[arg(long, env = "SOVD_MINTER_URL")]
    minter_url: Option<String>,
    /// Operator bearer token for the minter.
    #[arg(long, env = "SOVD_MINTER_OPERATOR_TOKEN")]
    operator_token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Surface the flash engine's progress (per-payload upload size/time/throughput,
    // staging, reset, commit) on stderr. Quiet by default for everything else;
    // override with RUST_LOG (e.g. `RUST_LOG=info` or `=debug` for more detail).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,sumo_sovd_flash_engine=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_target(false)
        .init();

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
        HubCmd::Channel {
            name,
            target_type,
            profile,
            json,
        } => {
            let tree = hub
                .channel_target_tree(&name, target_type.as_deref(), profile.as_deref())
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
        CaCmd::Enroll {
            id,
            key_id,
            csr,
            out,
        } => {
            let csr_der = std::fs::read(&csr)?;
            let resp = ca.enroll(&id, &key_id, &csr_der).await?;
            match (&resp.certificate_pem, &out) {
                (Some(pem), Some(p)) => {
                    std::fs::write(p, pem.as_bytes())?;
                    eprintln!("wrote device cert to {}", p.display());
                }
                (Some(pem), None) => print!("{pem}"),
                (None, _) => {} // device-decrypt: registration, no cert
            }
            match (&resp.serial, &resp.not_after) {
                (Some(serial), Some(na)) => eprintln!(
                    "enrolled '{}' key '{}' — cert serial {serial} (expires {na})",
                    resp.id, resp.key_id
                ),
                _ => eprintln!(
                    "enrolled '{}' key '{}' (registration, no cert)",
                    resp.id, resp.key_id
                ),
            }
        }
        CaCmd::MintKeystore { id, hub_url, out } => {
            let sw_pubkey = SoftwareClient::new(&hub_url).signer_pubkey().await?;
            let suit = ca.mint_keystore(&id, &hex::encode(sw_pubkey)).await?;
            match &out {
                Some(p) => {
                    std::fs::write(p, &suit)?;
                    eprintln!(
                        "wrote keystore SUIT ({} bytes) to {}",
                        suit.len(),
                        p.display()
                    );
                }
                None => std::io::stdout().write_all(&suit)?,
            }
        }
        CaCmd::CaCert { out } => {
            let pem = ca.ca_cert().await?;
            match &out {
                Some(p) => {
                    std::fs::write(p, pem.as_bytes())?;
                    eprintln!("wrote identity-root CA cert to {}", p.display());
                }
                None => print!("{pem}"),
            }
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
            target_type,
            profile,
            hub_url,
            plan,
        } => {
            let observed = orchestrator::read_rig_state(&args.url).await?;
            let desired = match (release, channel) {
                (Some(path), _) => serde_json::from_reader(std::fs::File::open(&path)?)?,
                (None, Some(name)) => SoftwareClient::new(&hub_url)
                    .channel_target_tree(&name, target_type.as_deref(), profile.as_deref())
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
            sel,
            hub_url,
            json,
        } => {
            let plan = orchestrator::apply_plan(&args.url, &hub_url, &sel.target(), None).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_apply(&plan);
            }
        }
        RigCmd::Flash {
            sel,
            hub_url,
            ca_url,
            auth,
            only,
            execute,
            json,
        } => {
            let target = sel.target();
            if execute {
                let token = rig_token(&auth, &args.url)?;
                let result = orchestrator::flash_execute(
                    &args.url,
                    &hub_url,
                    &ca_url,
                    &target,
                    &auth.device,
                    only.as_deref(),
                    false, // `rig flash`: respect each component's declared reset_kind
                    token,
                )
                .await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    print_flash_result(&result, true);
                }
            } else {
                let bundle = orchestrator::flash_bundle(
                    &args.url,
                    &hub_url,
                    &ca_url,
                    &target,
                    &auth.device,
                    only.as_deref(),
                )
                .await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&bundle)?);
                } else {
                    print_bundle(&bundle);
                }
            }
        }
        RigCmd::Campaign {
            sel,
            hub_url,
            ca_url,
            auth,
            execute,
            no_commit,
        } => {
            let target = sel.target();
            let plan = orchestrator::apply_plan(&args.url, &hub_url, &target, None).await?;
            let shipping: Vec<&orchestrator::ComponentApply> = plan
                .components
                .iter()
                .filter(|c| !c.ship.is_empty())
                .collect();
            if shipping.is_empty() {
                println!("up to date — nothing to flash for channel '{}'", sel.channel);
                return Ok(());
            }
            // Singleshot (irreversible) components each flash in their own
            // transaction; banked (reversible trial) ones flash together. Singleshot
            // first — its node reboot must not interrupt a banked trial.
            let (singleshot, banked): (Vec<&orchestrator::ComponentApply>, Vec<_>) = shipping
                .into_iter()
                .partition(|c| c.supports_rollback == Some(false));
            print_campaign(&sel.channel, &auth.device, &singleshot, &banked);
            if !execute {
                println!("\n(plan only — re-run with --execute to run the campaign)");
                return Ok(());
            }
            // Detection (the orchestrator half): refuse to start a campaign while
            // the rig has an unresolved prior transaction — a node reboot owed, or
            // a trial awaiting its verdict — instead of compounding it (the bug).
            // Names the components so the operator can resolve it first.
            let node_state = orchestrator::node_update_state(&args.url).await?;
            if node_state.is_unresolved() {
                anyhow::bail!(
                    "rig has an unresolved update transaction (phase {}, components {:?}) — \
                     reboot the node, or commit/rollback the pending update (./commit.sh or \
                     `rig rollback …`), before re-running the campaign",
                    node_state.phase,
                    node_state.components
                );
            }
            // Step through: each singleshot alone, then the banked group. After each
            // step, `finalize_step` gates on system health and (unless --no-commit)
            // commits the banked trial BEFORE the next step — a multi-reboot chain
            // must commit each good step rather than stack uncommitted trials (which
            // the device's verdict watchdog would auto-revert). An unhealthy step
            // rolls back and aborts the chain. By the banked step the singleshots are
            // committed + up-to-date, so a no-filter flash ships only the banked ones.
            for c in &singleshot {
                println!("\n== campaign step: {} (singleshot) ==", c.entity);
                let r = orchestrator::flash_execute(
                    &args.url,
                    &hub_url,
                    &ca_url,
                    &target,
                    &auth.device,
                    Some(c.entity.as_str()),
                    false, // singleshot (rt) reboots via its own declared reset_kind
                    rig_token(&auth, &args.url)?,
                )
                .await?;
                print_flash_result(&r, no_commit);
                finalize_step(&args.url, &c.entity, &r, no_commit, &auth).await?;
            }
            if !banked.is_empty() {
                println!("\n== campaign step: banked VMs ==");
                let r = orchestrator::flash_execute(
                    &args.url,
                    &hub_url,
                    &ca_url,
                    &target,
                    &auth.device,
                    None,
                    true, // banked step: activate the whole step with ONE node reboot
                    rig_token(&auth, &args.url)?,
                )
                .await?;
                print_flash_result(&r, no_commit);
                finalize_step(&args.url, "banked VMs", &r, no_commit, &auth).await?;
            }
            println!(
                "\ncampaign complete — {}",
                if no_commit {
                    "banked components in trial; commit when healthy (./commit.sh)."
                } else {
                    "each healthy step committed."
                }
            );
        }
        RigCmd::Commit {
            component,
            update,
            auth,
        } => {
            let token = rig_token(&auth, &args.url)?;
            let status = orchestrator::flash_commit(&args.url, &component, &update, token).await?;
            println!("{component} committed → {status}");
        }
        RigCmd::Rollback {
            component,
            update,
            auth,
        } => {
            let token = rig_token(&auth, &args.url)?;
            let status =
                orchestrator::flash_rollback(&args.url, &component, &update, token).await?;
            println!("{component} rolled back → {status}");
        }
        RigCmd::CommitTrials { auth } => {
            let token = rig_token(&auth, &args.url)?;
            orchestrator::flash_commit_trials(&args.url, token).await?;
            println!("node trials committed (the update session is the commit unit)");
        }
        RigCmd::RollbackTrials { auth } => {
            let token = rig_token(&auth, &args.url)?;
            orchestrator::flash_rollback_trials(&args.url, token).await?;
            println!("node trials rolled back");
        }
        RigCmd::Reset {
            component,
            update,
            auth,
        } => {
            let token = rig_token(&auth, &args.url)?;
            let status = orchestrator::flash_reset(&args.url, &component, &update, token).await?;
            println!("{component} reset → {status}");
        }
        RigCmd::InstallKeystore {
            suit,
            hub_url,
            auth,
        } => {
            let token = rig_token(&auth, &args.url)?;
            let suit_bytes = std::fs::read(&suit)?;
            let trust_anchor = SoftwareClient::new(&hub_url).signer_pubkey().await?;
            let result =
                orchestrator::flash_keystore(&args.url, suit_bytes, trust_anchor, token).await?;
            for c in &result.components {
                println!("hsm keystore → {}", c.state);
            }
            println!(
                "keystore installed — the rig now trusts Tower 2's signer; flash firmware next."
            );
        }
    }
    Ok(())
}

/// Build the SOVD bearer source for the flash engine: a fixed `--token` if given,
/// else a per-device JWT minted on demand from `sovd-token-helper`
/// (`--minter-url` + `--operator-token`). Errors if neither is supplied — every
/// op that reaches here mutates the device and the device enforces auth.
fn rig_token(auth: &AuthArgs, rig_url: &str) -> anyhow::Result<orchestrator::RigToken> {
    if let Some(t) = &auth.token {
        return Ok(orchestrator::RigToken::fixed(t.clone()));
    }
    if let Some(minter_url) = auth.minter_url.as_deref() {
        let operator_token = auth
            .operator_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--minter-url requires --operator-token"))?;
        return Ok(orchestrator::RigToken::minting(
            minter_url,
            operator_token,
            rig_url,
            None,
        ));
    }
    // No --token and no --minter-url. The device does NOT yet enforce auth on the
    // general SOVD path (only High-consequence routes like reset/factory-reset do
    // — the authorizer isn't wired into `create_router`). So most mutating ops
    // (keystore install, flash, commit) still succeed unauthenticated. Warn loudly
    // and proceed with an empty bearer rather than refusing the operator at the
    // front door: ops on the unenforced path go through; a reset will still 403
    // (correctly — it needs a real `reset:execute` token), which is the signal to
    // supply --token / --minter-url. Matches the example scripts' "auth optional
    // today" note; the token path returns the moment enforcement lands.
    eprintln!(
        "[sumo-provision] WARNING: no --token/--minter-url for device '{}' — \
         connecting UNAUTHENTICATED. Unenforced ops go through; High-consequence \
         ops (reset) will 403. Provide --token <jwt> or --minter-url + \
         --operator-token to authenticate.",
        auth.device
    );
    Ok(orchestrator::RigToken::fixed(String::new()))
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

/// Minimal system-health gate for the campaign's per-step auto-commit.
///
/// NOTE — TO ELABORATE: "good system state" is not yet fully specified. The real
/// gate should probe each running ECU's own health (heartbeat / app-level
/// liveness) and confirm the WHOLE system came back after a node reboot, not just
/// the components this step touched. For now we use the minimal definition agreed
/// with the operator: every component this step reset came back up — the engine
/// drove each to `Activated` (banked trial) or `Committed` (singleshot
/// write-through), none left `Failed`/`RolledBack`. `flash_execute` already polls
/// that, so an all-came-up result IS "each running ECU came up again". Grow the
/// health contract here when it's defined.
fn step_came_up(r: &orchestrator::FlashResult) -> bool {
    !r.components.is_empty()
        && r.components
            .iter()
            .all(|c| matches!(c.state.as_str(), "Activated" | "Committed"))
}

/// Health-gate a finished campaign step, then (unless `no_commit`) commit its
/// banked trial so the next step builds on a committed baseline. Banked
/// components sit in `Activated` (trial) and need an explicit commit; singleshot
/// ones are already `Committed` (write-through), nothing to do. An unhealthy step
/// rolls back whatever reached trial and aborts the campaign — never proceed on a
/// bad baseline.
async fn finalize_step(
    rig_url: &str,
    label: &str,
    r: &orchestrator::FlashResult,
    no_commit: bool,
    auth: &AuthArgs,
) -> anyhow::Result<()> {
    // The step's banked components sit in `Activated` (trial); singleshot ones are
    // already `Committed`. The trial is a step-level transaction, so commit (or roll
    // back) the whole set in ONE engine verdict — not once per component.
    let trial: Vec<(String, String)> = r
        .components
        .iter()
        .filter(|c| c.state == "Activated")
        .filter_map(|c| {
            c.update_id
                .as_deref()
                .map(|id| (c.entity.clone(), id.to_string()))
        })
        .collect();
    if !step_came_up(r) {
        eprintln!("  step '{label}' unhealthy — an ECU did not come up; rolling back + aborting.");
        if !trial.is_empty() {
            match orchestrator::flash_rollback_all(rig_url, &trial, rig_token(auth, rig_url)?).await {
                Ok(rolled) => {
                    for (entity, state) in rolled {
                        eprintln!("    rolled back {entity} → {state}");
                    }
                }
                Err(e) => eprintln!("    rollback failed: {e}"),
            }
        }
        anyhow::bail!("campaign aborted: step '{label}' left the system unhealthy");
    }
    if no_commit || trial.is_empty() {
        return Ok(()); // singleshot is write-through; or operator wants a manual verdict
    }
    for (entity, state) in orchestrator::flash_commit_all(rig_url, &trial, rig_token(auth, rig_url)?).await?
    {
        println!("  committed {entity} (healthy) → {state}");
    }
    Ok(())
}

fn print_flash_result(r: &orchestrator::FlashResult, trial_hint: bool) {
    if r.components.is_empty() {
        println!("nothing flashed — up to date for channel '{}'", r.channel);
        return;
    }
    println!("flashed device '{}' (channel '{}'):", r.device, r.channel);
    for c in &r.components {
        let id = c.update_id.as_deref().unwrap_or("-");
        println!("  {:<8} {:<12} update {}", c.entity, c.state, id);
    }
    // Banked components sit in a trial awaiting a verdict; singleshot ones come back
    // `Committed`. Show the manual-verdict hint only when the caller won't finalize
    // for us (`rig flash --execute`, or `campaign --no-commit`) — the auto-commit
    // campaign reports its own commit, so the hint would contradict it.
    let in_trial = |s: &str| matches!(s, "Staged" | "AwaitingSystemReboot" | "Activated");
    if trial_hint && r.components.iter().any(|c| in_trial(&c.state)) {
        println!(
            "\nin trial — the rig rebooted into the staged bank. When healthy, finalize:\n  ./commit.sh   (or `rig rollback …` to revert)"
        );
    }
}

/// Report the campaign plan: the ordered transactions to reach the target state,
/// grouped by update-mode (singleshot components each alone, then the banked group).
fn print_campaign(
    channel: &str,
    device: &str,
    singleshot: &[&orchestrator::ComponentApply],
    banked: &[&orchestrator::ComponentApply],
) {
    let steps = singleshot.len() + usize::from(!banked.is_empty());
    println!("Campaign — bring '{device}' to channel '{channel}' in {steps} step(s):");
    let mut n = 1;
    for c in singleshot {
        println!(
            "  Step {n} (singleshot, irreversible): {} — {} part(s), {} — write-through + node reboot",
            c.entity,
            c.ship.len(),
            human_size(c.ship_bytes())
        );
        n += 1;
    }
    if !banked.is_empty() {
        let names: Vec<&str> = banked.iter().map(|c| c.entity.as_str()).collect();
        let parts: usize = banked.iter().map(|c| c.ship.len()).sum();
        let bytes: u64 = banked.iter().map(|c| c.ship_bytes()).sum();
        println!(
            "  Step {n} (banked, trial): {} — {} part(s), {} — flash → reboot → trial → commit",
            names.join(", "),
            parts,
            human_size(bytes)
        );
    }
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
