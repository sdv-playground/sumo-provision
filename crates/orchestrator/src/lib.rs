//! sumo-provision orchestrator core.
//!
//! The orchestrator is the only component that talks to both the towers and a
//! rig. It observes a rig over SOVD as a [`wire::Tree`] ([`read_rig_state`]),
//! which [`wire::diff`] / [`wire::flash_plan`] compare against a desired tree (a
//! channel). [`apply_plan`] resolves a channel's ship-set against Tower 2 — the
//! read/resolve half of apply. Minting from Tower 1 and driving the SOVD
//! `/updates` flash land against the roadmap in `architecture.md`.

use std::sync::Arc;

use async_trait::async_trait;
use client::{ClientError, IdentityClient, MinterClient, SoftwareClient};
use serde::{Deserialize, Serialize};
use sovd_client::{SovdClient, SovdClientError};
use sumo_sovd_flash_engine::{
    EcuState, EcuStatus, EngineError, EngineTimeouts, FlashEngine, FlashJob, FlashPlan, Payload,
    PayloadSource, TokenSource, UpdateType,
};
use tokio::sync::Mutex;
use wire::{ContentHash, Entity, Part, Tree, UpdateMode};

/// SOVD data resource carrying each VM's signed installed inventory.
const INSTALLED_MANIFEST: &str = "x-sumo-installed-manifest";
/// SOVD data resource carrying each component's update capability.
const UPDATE_MODE: &str = "x-sumo-update-mode";

/// Error from the orchestrator.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sovd error: {0}")]
    Sovd(#[from] SovdClientError),
    #[error("tower client error: {0}")]
    Client(#[from] ClientError),
    #[error("flash engine error: {0}")]
    Engine(#[from] EngineError),
    #[error("Tower 2 has no blob {outer} for a shipped part")]
    PayloadMissing { outer: String },
    #[error("channel '{channel}' not found on Tower 2")]
    ChannelNotFound { channel: String },
    #[error("device '{id}' not registered in Tower 1")]
    DeviceNotFound { id: String },
    #[error("device '{id}' has no public key registered")]
    DeviceNoPubkey { id: String },
    #[error(
        "campaign mixes rollbackable {rollbackable:?} with irreversible {irreversible:?} — a \
         rollback would leave the device undefined; flash the irreversible component (e.g. the \
         HSM keystore) as its own campaign"
    )]
    MixedUpdateModes {
        rollbackable: Vec<String>,
        irreversible: Vec<String>,
    },
    #[error("could not parse installed manifest for {component}: {source}")]
    Manifest {
        component: String,
        source: serde_json::Error,
    },
    #[error("reading node update-state from the rig: {0}")]
    NodeState(String),
}

/// The node's update-transaction state, read from the device's
/// `x-sumo-update-state` vendor resource (`docs/design/node-update-state.md`).
/// The orchestrator polls this to detect an unresolved prior transaction (a node
/// reboot owed, or a trial awaiting its verdict) before starting a campaign step.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NodeUpdateState {
    pub phase: String,
    #[serde(default)]
    pub components: Vec<String>,
}

impl NodeUpdateState {
    /// True when a prior update transaction is unresolved — the node owes an
    /// activation reboot or a trial awaits its verdict — so a new campaign step
    /// must not start (it would compound the pending transaction).
    pub fn is_unresolved(&self) -> bool {
        matches!(self.phase.as_str(), "RebootPending" | "Trial")
    }
}

/// Read the device's node update-transaction state over SOVD
/// (`GET /vehicle/v1/data/x-sumo-update-state`). A device without the vendor
/// route (an older image) returns 404 → reported as `Idle`, so a fresh rig just
/// proceeds.
pub async fn node_update_state(rig_url: &str) -> Result<NodeUpdateState, Error> {
    let url = format!(
        "{}/vehicle/v1/data/x-sumo-update-state",
        rig_url.trim_end_matches('/')
    );
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| Error::NodeState(e.to_string()))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(NodeUpdateState {
            phase: "Idle".to_string(),
            components: Vec::new(),
        });
    }
    resp.error_for_status()
        .map_err(|e| Error::NodeState(e.to_string()))?
        .json::<NodeUpdateState>()
        .await
        .map_err(|e| Error::NodeState(e.to_string()))
}

/// Read a rig's observed state over SOVD as a [`wire::Tree`]: each component is
/// an entity, and the files in its signed installed manifest are its parts
/// (`kind = "file"`, `id = path`, `content = sha256`). Components with no signed
/// manifest come back as entities with no parts.
pub async fn read_rig_state(sovd_url: &str) -> Result<Tree, Error> {
    let client = SovdClient::new(sovd_url)?;
    let mut tree = Tree::default();
    for c in client.list_components().await? {
        let mut entity = Entity {
            kind: c.component_type.unwrap_or_default(),
            ..Default::default()
        };
        if let Some(m) = read_installed(&client, &c.id).await? {
            let label = format!("{} {}", m.identity.name, m.identity.version);
            entity.version = Some(label.trim().to_string());
            for f in m.files {
                if let Ok(content) = f.sha256.parse::<ContentHash>() {
                    entity.parts.push(Part {
                        kind: "file".to_string(),
                        id: f.path,
                        content,
                    });
                }
            }
        }
        entity.update_mode = read_update_mode(&client, &c.id).await?;
        tree.entities.insert(c.id, entity);
    }
    Ok(tree)
}

/// Read one component's `x-sumo-update-mode` capability; `None` when the device
/// doesn't serve it (older firmware) or the value doesn't parse. Always-available
/// on current devices — not gated on a committed manifest.
async fn read_update_mode(
    client: &SovdClient,
    component: &str,
) -> Result<Option<UpdateMode>, Error> {
    match client.read_data(component, UPDATE_MODE).await {
        Ok(resp) => Ok(serde_json::from_value(resp.value).ok()),
        Err(SovdClientError::ServerError {
            status: 404 | 501, ..
        }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Read one component's installed manifest; `None` when the component doesn't
/// expose it (404) or the rig doesn't implement that read (501).
async fn read_installed(
    client: &SovdClient,
    component: &str,
) -> Result<Option<InstalledManifest>, Error> {
    match client.read_data(component, INSTALLED_MANIFEST).await {
        Ok(resp) => {
            let manifest =
                serde_json::from_value(resp.value).map_err(|source| Error::Manifest {
                    component: component.to_string(),
                    source,
                })?;
            Ok(Some(manifest))
        }
        Err(SovdClientError::ServerError {
            status: 404 | 501, ..
        }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The installed manifest's JSON shape — the fields we project into the tree.
#[derive(Debug, Deserialize)]
struct InstalledManifest {
    #[serde(default)]
    identity: Identity,
    #[serde(default)]
    files: Vec<InstalledFile>,
}

#[derive(Debug, Default, Deserialize)]
struct Identity {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Deserialize)]
struct InstalledFile {
    path: String,
    sha256: String,
}

// --- apply plan ------------------------------------------------------------

/// Where a part's content lives in Tower 2 — the ciphertext blob to fetch.
#[derive(Debug, Clone, Serialize)]
pub struct BlobRef {
    pub outer: ContentHash,
    pub size: u64,
}

/// One part to ship to a component, resolved against Tower 2. `blob` is `None`
/// when the channel references content Tower 2 does not have (the build/publish
/// step is out of sync) — such a part cannot be flashed.
#[derive(Debug, Clone, Serialize)]
pub struct ShipPart {
    pub part: String,
    pub kind: String,
    pub content: ContentHash,
    pub blob: Option<BlobRef>,
}

/// One component's slice of the apply plan: what ships, and how many parts the
/// device reuses from its own active bank.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentApply {
    pub entity: String,
    pub version: Option<String>,
    pub ship: Vec<ShipPart>,
    pub reuse: usize,
    /// The component's rollback capability, from the twin's `x-sumo-update-mode`:
    /// `Some(true)` = banked (reversible trial), `Some(false)` = singleshot
    /// (irreversible), `None` = not reported. Drives the campaign's step grouping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_rollback: Option<bool>,
}

/// Total bytes a component would ship (sum of its resolved blob sizes).
impl ComponentApply {
    pub fn ship_bytes(&self) -> u64 {
        self.ship
            .iter()
            .filter_map(|s| s.blob.as_ref().map(|b| b.size))
            .sum()
    }
}

/// The executable plan to bring a rig to a channel's desired state: per
/// component, the ship-set resolved against Tower 2 (everything else the device
/// seeds from its own active bank). Built by [`apply_plan`]; the flash itself
/// (drive the SOVD `/updates` wire per component) executes this.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ApplyPlan {
    pub channel: String,
    pub components: Vec<ComponentApply>,
}

impl ApplyPlan {
    /// Total bytes that must cross the wire — the sum of resolved ship blobs.
    pub fn ship_bytes(&self) -> u64 {
        self.components
            .iter()
            .flat_map(|c| &c.ship)
            .filter_map(|s| s.blob.as_ref().map(|b| b.size))
            .sum()
    }

    /// Ship parts Tower 2 cannot serve — `(entity, part)` for each.
    pub fn missing(&self) -> Vec<(&str, &str)> {
        self.components
            .iter()
            .flat_map(|c| {
                c.ship
                    .iter()
                    .filter(|s| s.blob.is_none())
                    .map(move |s| (c.entity.as_str(), s.part.as_str()))
            })
            .collect()
    }

    /// True when nothing ships — the rig already matches the channel.
    pub fn is_noop(&self) -> bool {
        self.components.iter().all(|c| c.ship.is_empty())
    }
}

/// Which channel target to resolve: a `channel`, optionally narrowed to one
/// `(target_type, profile)` when that channel serves several targets — the
/// multi-profile selector (software-tower migration `0005`). Both `None`
/// resolves the channel's single target, the common case.
#[derive(Debug, Clone)]
pub struct ChannelTarget {
    pub channel: String,
    pub target_type: Option<String>,
    pub profile: Option<String>,
}

impl ChannelTarget {
    /// A channel with no `(target_type, profile)` narrowing — its single target.
    pub fn channel(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            target_type: None,
            profile: None,
        }
    }

    /// Human label for diagnostics: the channel, plus any narrowing in parens.
    fn label(&self) -> String {
        match (&self.target_type, &self.profile) {
            (None, None) => self.channel.clone(),
            (tt, pf) => format!(
                "{} (target_type={}, profile={})",
                self.channel,
                tt.as_deref().unwrap_or("*"),
                pf.as_deref().unwrap_or("*"),
            ),
        }
    }
}

/// Plan how to bring the rig at `rig_url` to the desired state on `target`
/// (resolved from Tower 2 at `hub_url`). Reads the rig over SOVD, resolves the
/// target's desired tree, computes the per-component [`wire::flash_plan`], and
/// resolves each shipped part against Tower 2's index — confirming Tower 2 can
/// actually serve it and totalling the transfer. This is the read/resolve half
/// of apply; flashing drives the SOVD `/updates` wire per component from it.
pub async fn apply_plan(
    rig_url: &str,
    hub_url: &str,
    target: &ChannelTarget,
    only: Option<&str>,
) -> Result<ApplyPlan, Error> {
    let observed = read_rig_state(rig_url).await?;
    let hub = SoftwareClient::new(hub_url);
    let desired = hub
        .channel_target_tree(
            &target.channel,
            target.target_type.as_deref(),
            target.profile.as_deref(),
        )
        .await?
        .ok_or_else(|| Error::ChannelNotFound {
            channel: target.label(),
        })?;
    let plan = wire::flash_plan(&observed, &desired);

    let mut components = Vec::new();
    for (path, entity) in &desired.entities {
        if let Some(o) = only {
            if path != o {
                continue;
            }
        }
        let mut ship = Vec::new();
        let mut reuse = 0;
        for p in plan.parts.iter().filter(|p| p.entity == *path) {
            match p.plan {
                wire::PartPlan::Reuse => reuse += 1,
                wire::PartPlan::Ship => {
                    let blob = hub.artifact_exists(&p.content).await?.map(|a| BlobRef {
                        outer: a.outer,
                        size: a.size,
                    });
                    ship.push(ShipPart {
                        part: p.part.clone(),
                        kind: p.kind.clone(),
                        content: p.content,
                        blob,
                    });
                }
            }
        }
        if !ship.is_empty() || reuse > 0 {
            components.push(ComponentApply {
                entity: path.clone(),
                version: entity.version.clone(),
                ship,
                reuse,
                supports_rollback: observed
                    .entities
                    .get(path)
                    .and_then(|e| e.update_mode.as_ref())
                    .map(|m| m.supports_rollback),
            });
        }
    }
    Ok(ApplyPlan {
        channel: target.channel.clone(),
        components,
    })
}

// --- flash bundle (dry) ----------------------------------------------------

/// A payload to upload alongside the envelope — referenced by SUIT `#uri`, the
/// ciphertext fetched from Tower 2's blob store by `outer`.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadRef {
    pub uri: String,
    pub outer: ContentHash,
    pub size: u64,
}

/// One component's flash bundle: the signed envelope + its payload references.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentFlash {
    pub entity: String,
    pub envelope_bytes: usize,
    pub payloads: Vec<PayloadRef>,
}

/// The per-device flash bundle for a channel — exactly what would be uploaded
/// over SOVD, assembled without touching the rig (the dry half of the flash).
#[derive(Debug, Clone, Serialize, Default)]
pub struct FlashBundle {
    pub channel: String,
    pub device: String,
    pub components: Vec<ComponentFlash>,
}

/// Assemble the per-device flash bundle to bring the rig to `target`'s desired
/// state: the ship-set ([`apply_plan`]), then a signed SUIT envelope per
/// component (built by Tower 2, with the CEK re-wrapped to the device's Tower 1
/// key) plus its payload references — exactly what the flash would upload over
/// SOVD, assembled without touching the rig.
pub async fn flash_bundle(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    only: Option<&str>,
) -> Result<FlashBundle, Error> {
    let plan = apply_plan(rig_url, hub_url, target, only).await?;
    let pubkey = device_pubkey(ca_url, device_id).await?;

    let hub = SoftwareClient::new(hub_url);
    let mut components = Vec::new();
    for c in &plan.components {
        if c.ship.is_empty() {
            continue;
        }
        let parts: Vec<(String, ContentHash)> =
            c.ship.iter().map(|s| (s.part.clone(), s.content)).collect();
        let envelope = hub
            .build_envelope(&pubkey, device_id, &c.entity, &parts, 1)
            .await?;
        let payloads = c
            .ship
            .iter()
            .filter_map(|s| {
                s.blob.as_ref().map(|b| PayloadRef {
                    uri: format!("#{}", s.part),
                    outer: b.outer,
                    size: b.size,
                })
            })
            .collect();
        components.push(ComponentFlash {
            entity: c.entity.clone(),
            envelope_bytes: envelope.len(),
            payloads,
        });
    }
    Ok(FlashBundle {
        channel: target.channel.clone(),
        device: device_id.to_string(),
        components,
    })
}

// --- flash execute (wet) ---------------------------------------------------

/// Bearer-token source for the flash engine's SOVD calls — replaces the old
/// `api_key`-as-Bearer hack. Either a token the operator supplied directly, or a
/// per-device JWT minted from `sovd-token-helper`. Minting is cached for the run
/// (one mint per flash, device-scoped `*`) — matching the single-token flow the
/// fork used, and covering every component plus the engine's entity-root restart.
pub enum RigToken {
    /// A pre-supplied bearer JWT, used verbatim for every component.
    Static(String),
    /// Mint a per-device JWT on first use, then cache it. The token's audience is
    /// the rig's ecu_id — its HSM device-key thumbprint, read from `x-sumo-id` at
    /// mint time — which is what the device verifies, NOT its roster name.
    Mint {
        minter: MinterClient,
        rig_url: String,
        ttl_secs: Option<u64>,
        cached: Mutex<Option<String>>,
    },
}

impl RigToken {
    /// Use a fixed operator-supplied bearer token.
    pub fn fixed(jwt: impl Into<String>) -> Self {
        RigToken::Static(jwt.into())
    }

    /// Mint per-device JWTs from `minter_url` (operator-authenticated to `/mint`).
    /// `rig_url` is the device's SOVD base — the audience is resolved from its
    /// `x-sumo-id` (the ecu_id) at mint time, never supplied as a name.
    pub fn minting(
        minter_url: impl Into<String>,
        operator_token: impl Into<String>,
        rig_url: impl Into<String>,
        ttl_secs: Option<u64>,
    ) -> Self {
        RigToken::Mint {
            minter: MinterClient::new(minter_url, operator_token),
            rig_url: rig_url.into(),
            ttl_secs,
            cached: Mutex::new(None),
        }
    }
}

/// GET a small `x-sumo-*` id from the rig, trimmed + unquoted. The `aud` (ecu_id)
/// and `boot_id` a destructive token must carry are read here — the same ids
/// `factory-reset.sh` reads, never the roster name and never a stale boot.
async fn fetch_rig_id(rig_url: &str, path: &str, what: &str) -> Result<String, EngineError> {
    let url = format!("{}{path}", rig_url.trim_end_matches('/'));
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| EngineError::Internal(format!("read {what} from {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(EngineError::Internal(format!(
            "read {what}: {url} returned HTTP {}",
            resp.status()
        )));
    }
    let id = resp
        .text()
        .await
        .map_err(|e| EngineError::Internal(format!("read {what} body: {e}")))?;
    let id = id.trim().trim_matches('"').to_string();
    if id.is_empty() {
        return Err(EngineError::Internal(format!("{url} returned an empty {what}")));
    }
    Ok(id)
}

/// The rig's ecu_id (its HSM device-key thumbprint) — the token `aud`.
async fn fetch_rig_ecu_id(rig_url: &str) -> Result<String, EngineError> {
    fetch_rig_id(rig_url, "/vehicle/v1/components/hsm/x-sumo-id", "ecu id").await
}

/// The rig's live boot nonce — the §7.1 freshness `boot_id` a destructive token
/// binds to (read fresh, right before minting).
async fn fetch_rig_boot_id(rig_url: &str) -> Result<String, EngineError> {
    fetch_rig_id(rig_url, "/vehicle/v1/status/x-sumo-boot-id", "boot id").await
}

#[async_trait]
impl TokenSource for RigToken {
    async fn token(&self, _component_id: &str) -> Result<String, EngineError> {
        match self {
            RigToken::Static(jwt) => Ok(jwt.clone()),
            RigToken::Mint {
                minter,
                rig_url,
                ttl_secs,
                cached,
            } => {
                let mut guard = cached.lock().await;
                if let Some(tok) = guard.as_ref() {
                    return Ok(tok.clone());
                }
                // The token's `aud` is the rig's ecu_id (its HSM device-key
                // thumbprint) and its `boot_id` is the rig's live boot nonce — both
                // resolved from the device (NOT the roster name, NOT a stale boot),
                // the same ids factory-reset.sh reads. Destructive routes bind both.
                let ecu_id = fetch_rig_ecu_id(rig_url).await?;
                let boot_id = fetch_rig_boot_id(rig_url).await?;
                let minted = minter
                    .mint(&ecu_id, &["*".to_string()], Some(&boot_id), *ttl_secs)
                    .await
                    .map_err(|e| EngineError::Internal(format!("mint token: {e}")))?;
                *guard = Some(minted.token.clone());
                Ok(minted.token)
            }
        }
    }
}

/// One component's flash result.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentFlashResult {
    pub entity: String,
    /// The `/updates` package id — pass to `commit`/`rollback` for the verdict.
    pub update_id: Option<String>,
    pub state: String,
}

/// The result of a flash across a channel's components.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FlashResult {
    pub channel: String,
    pub device: String,
    pub components: Vec<ComponentFlashResult>,
}

/// Build the engine [`FlashPlan`] to bring the rig to `target`'s desired state,
/// plus the SUIT trust anchor the engine validates manifests against. For each
/// shipping component: a Tower-2 signed envelope (CEK re-wrapped to the device)
/// and its ciphertext payloads fetched from Tower 2. Payloads are buffered
/// (`PayloadSource::Bytes`) — fine for the offboard orchestrator; the onboard
/// adapter streams instead.
pub async fn build_flash_plan(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    only: Option<&str>,
) -> Result<(FlashPlan, Vec<u8>), Error> {
    let plan = apply_plan(rig_url, hub_url, target, only).await?;
    let pubkey = device_pubkey(ca_url, device_id).await?;
    let hub = SoftwareClient::new(hub_url);
    let trust_anchor = hub.signer_pubkey().await?;

    let mut jobs = Vec::new();
    for c in &plan.components {
        if c.ship.is_empty() {
            continue;
        }
        let parts: Vec<(String, ContentHash)> =
            c.ship.iter().map(|s| (s.part.clone(), s.content)).collect();
        let envelope = hub
            .build_envelope(&pubkey, device_id, &c.entity, &parts, 1)
            .await?;
        let mut payloads = Vec::new();
        for s in &c.ship {
            if let Some(b) = &s.blob {
                let ciphertext =
                    hub.get_blob(&b.outer)
                        .await?
                        .ok_or_else(|| Error::PayloadMissing {
                            outer: b.outer.to_prefixed(),
                        })?;
                payloads.push(Payload {
                    uri: format!("#{}", s.part),
                    source: PayloadSource::Bytes(ciphertext),
                });
            }
        }
        jobs.push(FlashJob {
            component_id: c.entity.clone(),
            gateway_id: None,
            envelope,
            payloads,
        });
    }
    Ok((FlashPlan { jobs }, trust_anchor))
}

/// Drive the rig to `target`'s desired state over SOVD via the shared flash
/// engine: build the plan, stage every shipping component, then reset. The engine
/// reads each component's `reset_kind` off the wire and coalesces a
/// `RequiresEcuReset` (RT / host-OS) into a single node reboot — so the new
/// firmware actually boots, in a reversible trial. The verdict — `commit` or
/// `rollback` — is a separate step taken once the rig is confirmed healthy.
/// **Destructive: mutates the rig.**
#[allow(clippy::too_many_arguments)] // rig + two tower URLs, selectors, flags — all distinct
pub async fn flash_execute(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    only: Option<&str>,
    reboot_to_activate: bool,
    token: RigToken,
) -> Result<FlashResult, Error> {
    let (plan, trust_anchor) =
        build_flash_plan(rig_url, hub_url, ca_url, target, device_id, only).await?;
    // `reboot_to_activate` (the workshop campaign) activates the whole step via one
    // node reboot — both banks boot their new images together, no racy per-VM
    // relaunch. The onboard/field path leaves it false (no orchestrator reboot;
    // activation waits for the next power cycle).
    let engine = FlashEngine::new(
        rig_url,
        Arc::new(token),
        trust_anchor,
        EngineTimeouts::default(),
    )
    .with_force_ecu_reset(reboot_to_activate);
    // No-mix guard, scoped to this (possibly `--only`-filtered) plan: reject a
    // mix of rollbackable + irreversible components, reading each job's
    // x-sumo-update-mode off the device. `--only` is how a singleshot component
    // (e.g. rt) flashes in its own transaction.
    engine.guard(&plan).await?;
    let mut ecus = engine.stage_all(&plan).await?;
    engine.reset_all(&mut ecus).await?;
    Ok(FlashResult {
        channel: target.channel.clone(),
        device: device_id.to_string(),
        components: ecus.iter().map(component_result).collect(),
    })
}

/// Install a pre-built, factory-signed HSM keystore SUIT on the rig's `hsm`
/// component (the device's trust anchors — minted by Tower 1 from the device
/// CSR). The SUIT is NOT a Tower-2 envelope: it carries an integrated
/// `#hsm-keys` payload, so the job has no detached payloads. `trust_anchor` is
/// the firmware signer pubkey (Tower 2's): the keystore is factory-signed, so it
/// fails validation against that anchor and the engine treats it as opaque,
/// uploading the manifest only — the device re-validates against the well-known
/// factory key (mirrors `sumo-campaign flash hsm --trust-anchor`). The anchor
/// must be a valid COSE_Key (an empty one panics the validator). `hsm` is
/// singleshot, so staging completes it; no reset/trial. Flash this ALONE — never
/// mixed with banked components. **Destructive: mutates the rig.**
pub async fn flash_keystore(
    rig_url: &str,
    hsm_suit: Vec<u8>,
    trust_anchor: Vec<u8>,
    token: RigToken,
) -> Result<FlashResult, Error> {
    let plan = FlashPlan {
        jobs: vec![FlashJob {
            component_id: "hsm".to_string(),
            gateway_id: None,
            envelope: hsm_suit,
            payloads: Vec::new(),
        }],
    };
    let engine = FlashEngine::new(
        rig_url,
        Arc::new(token),
        trust_anchor,
        EngineTimeouts::default(),
    );
    let ecus = engine.stage_all(&plan).await?;
    Ok(FlashResult {
        channel: "(keystore)".to_string(),
        device: String::new(),
        components: ecus.iter().map(component_result).collect(),
    })
}

// --- verdict (reset / commit / rollback) -----------------------------------

/// Reset a staged component so it boots the trial bank — via the engine, which
/// reads the component's `reset_kind` and either restarts it locally or reboots
/// the parent ECU/node (`RequiresEcuReset`), then polls it to `Activated`.
/// Normally `flash_execute` already does this; exposed as a manual escape hatch.
pub async fn flash_reset(
    rig_url: &str,
    component: &str,
    update_id: &str,
    token: RigToken,
) -> Result<String, Error> {
    let engine = verdict_engine(rig_url, token, false);
    let mut ecus = [ecu_status(component, update_id, EcuState::Staged)];
    engine.reset_all(&mut ecus).await?;
    Ok(format!("{:?}", ecus[0].state))
}

/// Commit a staged update once its trial boot is healthy: re-attach and commit.
pub async fn flash_commit(
    rig_url: &str,
    component: &str,
    update_id: &str,
    token: RigToken,
) -> Result<String, Error> {
    let engine = verdict_engine(rig_url, token, false);
    let mut ecus = [ecu_status(component, update_id, EcuState::Activated)];
    engine.commit_all(&mut ecus).await?;
    Ok(format!("{:?}", ecus[0].state))
}

/// Roll a staged update back: re-attach and revert to the prior bank.
pub async fn flash_rollback(
    rig_url: &str,
    component: &str,
    update_id: &str,
    token: RigToken,
) -> Result<String, Error> {
    let engine = verdict_engine(rig_url, token, false);
    let mut ecus = [ecu_status(component, update_id, EcuState::Activated)];
    engine.rollback_all(&mut ecus).await?;
    Ok(format!("{:?}", ecus[0].state))
}

/// Commit a whole step's banked components in ONE verdict: the trial is a
/// step-level transaction, so the engine's `commit_all` runs once over the set
/// rather than once per component. `updates` is `(component, update_id)` pairs;
/// returns each `(component, final state)`.
pub async fn flash_commit_all(
    rig_url: &str,
    updates: &[(String, String)],
    token: RigToken,
) -> Result<Vec<(String, String)>, Error> {
    let engine = verdict_engine(rig_url, token, true);
    let mut ecus: Vec<EcuStatus> = updates
        .iter()
        .map(|(c, id)| ecu_status(c, id, EcuState::Activated))
        .collect();
    engine.commit_all(&mut ecus).await?;
    Ok(ecus
        .iter()
        .map(|e| (e.component_id.clone(), format!("{:?}", e.state)))
        .collect())
}

/// Roll a whole step's banked components back in ONE verdict — see [`flash_commit_all`].
pub async fn flash_rollback_all(
    rig_url: &str,
    updates: &[(String, String)],
    token: RigToken,
) -> Result<Vec<(String, String)>, Error> {
    let engine = verdict_engine(rig_url, token, true);
    let mut ecus: Vec<EcuStatus> = updates
        .iter()
        .map(|(c, id)| ecu_status(c, id, EcuState::Activated))
        .collect();
    engine.rollback_all(&mut ecus).await?;
    Ok(ecus
        .iter()
        .map(|e| (e.component_id.clone(), format!("{:?}", e.state)))
        .collect())
}

/// Commit the whole node's in-trial set in ONE verdict, without enumerating
/// components — the device resolves the in-trial set from NV. This is the
/// manual `commit-trials` verb (and what `commit.sh` runs after a node-reboot
/// update): the update *session* is the commit unit, never a single component.
pub async fn flash_commit_trials(rig_url: &str, token: RigToken) -> Result<(), Error> {
    verdict_engine(rig_url, token, true)
        .commit_node_trials()
        .await?;
    Ok(())
}

/// Roll the whole node's in-trial set back in ONE verdict — see [`flash_commit_trials`].
pub async fn flash_rollback_trials(rig_url: &str, token: RigToken) -> Result<(), Error> {
    verdict_engine(rig_url, token, true)
        .rollback_node_trials()
        .await?;
    Ok(())
}

// --- adapter helpers -------------------------------------------------------

/// Resolve a device's registered public key from Tower 1.
async fn device_pubkey(ca_url: &str, device_id: &str) -> Result<String, Error> {
    let device = IdentityClient::new(ca_url)
        .get_device(device_id)
        .await?
        .ok_or_else(|| Error::DeviceNotFound {
            id: device_id.to_string(),
        })?;
    device.pubkey.ok_or_else(|| Error::DeviceNoPubkey {
        id: device_id.to_string(),
    })
}

/// An engine for the verdict verbs (reset/commit/rollback). These never classify
/// a manifest, so the trust anchor is unused — an empty one is correct.
/// `force_ecu_reset` selects the node-level verdict (one verdict for the whole
/// step, finalized from NV after a node reboot — the update *session* is the
/// commit unit) over the per-component path (a live local-reset session).
fn verdict_engine(rig_url: &str, token: RigToken, force_ecu_reset: bool) -> FlashEngine {
    FlashEngine::new(
        rig_url,
        Arc::new(token),
        Vec::new(),
        EngineTimeouts::default(),
    )
    .with_force_ecu_reset(force_ecu_reset)
}

/// A single-component [`EcuStatus`] reconstructed from CLI args, so the verdict
/// verbs can drive the engine's per-phase methods one component at a time.
fn ecu_status(component: &str, update_id: &str, state: EcuState) -> EcuStatus {
    EcuStatus {
        component_id: component.to_string(),
        gateway_id: None,
        state,
        update_type: UpdateType::Firmware,
        active_version: None,
        previous_version: None,
        error: None,
        update_id: Some(update_id.to_string()),
    }
}

fn component_result(s: &EcuStatus) -> ComponentFlashResult {
    ComponentFlashResult {
        entity: s.component_id.clone(),
        update_id: s.update_id.clone(),
        state: format!("{:?}", s.state),
    }
}
