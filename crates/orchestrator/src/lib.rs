//! sumo-provision orchestrator core.
//!
//! The orchestrator is the only component that talks to both the towers and a
//! rig. It observes a rig over SOVD as a [`wire::Tree`] ([`read_rig_state`]),
//! which [`wire::diff`] / [`wire::flash_plan`] compare against a desired tree (a
//! channel) for the read-only preview ([`apply_plan`]). The push itself relays
//! Tower 2's signed **L1 campaign** for the device ([`build_flash_plan`] /
//! [`campaign_execute`]): Tower 2 does the diff + per-device assembly and signs
//! the result, so the orchestrator fans the L1 out into per-component L2 images
//! and drives the SOVD `/updates` flash over the shared engine — never rebuilding
//! the plan itself. It fetches each part's ciphertext from the blob store to push
//! alongside the manifest, except for a whole component the vehicle already carries
//! (diffed against its self-report): that one pushes the manifest alone and the
//! device copy-forwards the content from its own active bank, digest-verified.

use std::sync::Arc;

use async_trait::async_trait;
use client::{ClientError, IdentityClient, MinterClient, SoftwareClient};
use serde::{Deserialize, Serialize};
use sovd_client::{SovdClient, SovdClientError};
use sumo_codec::decode::decode_envelope;
use sumo_onboard::Manifest;
use sumo_sovd_flash_engine::{
    CameUp, CampaignStep, EcuState, EcuStatus, EngineError, EngineTimeouts, FlashEngine, FlashJob,
    FlashPlan, Payload, PayloadSource, TokenSource, UpdateType,
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
    #[error("decoding the signed L1 campaign from Tower 2: {0}")]
    DecodeL1(String),
    #[error("the L1 image for component '{component}' is malformed: {reason}")]
    BadL2 { component: String, reason: String },
    #[error(
        "the L1 push needs an explicit device and architecture — channel '{channel}' resolves a \
         (channel, device, architecture) target"
    )]
    L1NeedsSelector { channel: String },
    #[error("encoding the vehicle state for the L1 request: {0}")]
    StateEncode(String),
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

/// A reqwest client for the device's SOVD endpoint. `ca_cert_pem`, when set, pins
/// that CA root (PEM) — the tower identity root — and verifies the device's
/// `tls-identity` leaf against it (dialling `<id>.local`). When `None`, falls back
/// to the `insecure` toggle: the `curl -k` equivalent — skip TLS cert verification
/// (the device's leaf has a SAN that won't match a `127.0.0.1` dial; dev/interim
/// until the device's `.local` SAN + mDNS land). `None` + `insecure == false` is
/// full verification, identical to the previous bare `reqwest::get`. Scoped to the
/// device — the towers (Tower 1/2, the minter) are plain HTTP and keep full
/// verification by construction. The same CA-trust seam as the SovdClient /
/// FlashClient builders.
fn device_http_client(
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> reqwest::Result<reqwest::Client> {
    let builder = reqwest::Client::builder();
    let builder = match ca_cert_pem {
        Some(pem) => builder.add_root_certificate(reqwest::Certificate::from_pem(pem)?),
        None => builder.danger_accept_invalid_certs(insecure),
    };
    builder.build()
}

/// Read the device's node update-transaction state over SOVD
/// (`GET /vehicle/v1/data/x-sumo-update-state`). A device without the vendor
/// route (an older image) returns 404 → reported as `Idle`, so a fresh rig just
/// proceeds.
pub async fn node_update_state(
    rig_url: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<NodeUpdateState, Error> {
    let url = format!(
        "{}/vehicle/v1/data/x-sumo-update-state",
        rig_url.trim_end_matches('/')
    );
    let resp = device_http_client(insecure, ca_cert_pem)
        .map_err(|e| Error::NodeState(e.to_string()))?
        .get(&url)
        .send()
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
pub async fn read_rig_state(
    sovd_url: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<Tree, Error> {
    let client = SovdClient::new_verifying(sovd_url, insecure, ca_cert_pem)?;
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
/// `(device, architecture)` when that channel serves several targets — the
/// resolution selector (software-tower migration `0007`). Both `None` resolves
/// the channel's single target, the common case.
#[derive(Debug, Clone)]
pub struct ChannelTarget {
    pub channel: String,
    pub device: Option<String>,
    pub architecture: Option<String>,
}

impl ChannelTarget {
    /// A channel with no `(device, architecture)` narrowing — its single target.
    pub fn channel(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            device: None,
            architecture: None,
        }
    }

    /// Human label for diagnostics: the channel, plus any narrowing in parens.
    fn label(&self) -> String {
        match (&self.device, &self.architecture) {
            (None, None) => self.channel.clone(),
            (dev, arch) => format!(
                "{} (device={}, architecture={})",
                self.channel,
                dev.as_deref().unwrap_or("*"),
                arch.as_deref().unwrap_or("*"),
            ),
        }
    }
}

/// Plan how to bring the rig at `rig_url` to the desired state on `target`
/// (resolved from Tower 2 at `hub_url`). Reads the rig over SOVD, resolves the
/// target's desired tree, computes the per-component [`wire::flash_plan`], and
/// resolves each shipped part against Tower 2's index — confirming Tower 2 can
/// actually serve it and totalling the transfer. This is the **read-only preview**
/// (and the `rig campaign` "anything to do?" gate); the push itself no longer
/// diffs client-side — it relays Tower 2's signed L1 (see [`build_flash_plan`]).
pub async fn apply_plan(
    rig_url: &str,
    hub_url: &str,
    target: &ChannelTarget,
    only: Option<&str>,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<ApplyPlan, Error> {
    let observed = read_rig_state(rig_url, insecure, ca_cert_pem).await?;
    let hub = SoftwareClient::new(hub_url);
    let desired = hub
        .channel_target_tree(
            &target.channel,
            target.device.as_deref(),
            target.architecture.as_deref(),
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
#[allow(clippy::too_many_arguments)] // rig + two tower URLs, selector, flags — all distinct
pub async fn flash_bundle(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    only: Option<&str>,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<FlashBundle, Error> {
    let plan = apply_plan(rig_url, hub_url, target, only, insecure, ca_cert_pem).await?;
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
/// per-device JWT minted from `sovd-token-helper` (device-scoped `*`, covering
/// every component plus the engine's entity-root restart). The minted token is
/// **bound to the device's boot** (`boot_id`, which the boot-bound reset route
/// verifies), so it is cached **per boot**: a multi-step campaign that reboots
/// more than once re-mints once the live `boot_id` moves — only a cheap
/// `x-sumo-boot-id` GET is per-call; the mint itself happens once per boot.
pub enum RigToken {
    /// A pre-supplied bearer JWT, used verbatim for every component.
    Static(String),
    /// Mint a per-device JWT, re-minting when the device's boot changes. The
    /// token's audience is the rig's ecu_id — its HSM device-key thumbprint, read
    /// from `x-sumo-id` — which is what the device verifies, NOT its roster name.
    Mint {
        minter: MinterClient,
        rig_url: String,
        ttl_secs: Option<u64>,
        /// Skip TLS cert verification when reading the device's `boot_id`/`aud`
        /// to mint against (the `curl -k` equivalent; mirrors the CLI `--insecure`).
        /// `false` = full verification.
        insecure: bool,
        /// Pin this CA root (PEM) when reading the device's `boot_id`/`aud` — the
        /// verifying alternative to `insecure` (mirrors the CLI `--cacert`). `None`
        /// = the `insecure` behaviour.
        ca_cert_pem: Option<Vec<u8>>,
        /// `(boot_id, token)` — the token minted for that boot. Re-minted when the
        /// live boot_id differs (a reboot rotated it).
        cached: Mutex<Option<(String, String)>>,
    },
}

impl RigToken {
    /// Use a fixed operator-supplied bearer token.
    pub fn fixed(jwt: impl Into<String>) -> Self {
        RigToken::Static(jwt.into())
    }

    /// Mint per-device JWTs from `minter_url` (operator-authenticated to `/mint`).
    /// `rig_url` is the device's SOVD base — the audience is resolved from its
    /// `x-sumo-id` (the ecu_id) at mint time, never supplied as a name. `insecure`
    /// (the CLI `--insecure`) skips cert verification on those device reads only;
    /// `ca_cert_pem` (the CLI `--cacert`) instead pins a CA root to verify them.
    /// The minter itself is reached over plain HTTP regardless.
    pub fn minting(
        minter_url: impl Into<String>,
        operator_token: impl Into<String>,
        rig_url: impl Into<String>,
        ttl_secs: Option<u64>,
        insecure: bool,
        ca_cert_pem: Option<Vec<u8>>,
    ) -> Self {
        RigToken::Mint {
            minter: MinterClient::new(minter_url, operator_token),
            rig_url: rig_url.into(),
            ttl_secs,
            insecure,
            ca_cert_pem,
            cached: Mutex::new(None),
        }
    }
}

/// GET a small `x-sumo-*` id from the rig, trimmed + unquoted. The `aud` (ecu_id)
/// and `boot_id` a destructive token must carry are read here — the same ids
/// `factory-reset.sh` reads, never the roster name and never a stale boot.
async fn fetch_rig_id(
    rig_url: &str,
    path: &str,
    what: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<String, EngineError> {
    let url = format!("{}{path}", rig_url.trim_end_matches('/'));
    let resp = device_http_client(insecure, ca_cert_pem)
        .map_err(|e| EngineError::Internal(format!("build http client: {e}")))?
        .get(&url)
        .send()
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
        return Err(EngineError::Internal(format!(
            "{url} returned an empty {what}"
        )));
    }
    Ok(id)
}

/// The rig's ecu_id (its HSM device-key thumbprint) — the token `aud`.
async fn fetch_rig_ecu_id(
    rig_url: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<String, EngineError> {
    fetch_rig_id(
        rig_url,
        "/vehicle/v1/components/hsm/x-sumo-id",
        "ecu id",
        insecure,
        ca_cert_pem,
    )
    .await
}

/// The rig's live boot nonce — the §7.1 freshness `boot_id` a destructive token
/// binds to (read fresh, right before minting).
async fn fetch_rig_boot_id(
    rig_url: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<String, EngineError> {
    fetch_rig_id(
        rig_url,
        "/vehicle/v1/status/x-sumo-boot-id",
        "boot id",
        insecure,
        ca_cert_pem,
    )
    .await
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
                insecure,
                ca_cert_pem,
                cached,
            } => {
                // The minted token's `boot_id` is bound at the device by the
                // boot-bound reset route, so it is only valid for the current boot.
                // Read the live boot_id first; reuse the cached token only while the
                // boot hasn't moved, and re-mint when it has (a campaign step that
                // rebooted). This makes a multi-reboot campaign work with one
                // `RigToken` — only this GET is per-call, the mint is once per boot.
                let boot_id = fetch_rig_boot_id(rig_url, *insecure, ca_cert_pem.as_deref()).await?;
                let mut guard = cached.lock().await;
                if let Some((cached_boot, tok)) = guard.as_ref() {
                    if cached_boot == &boot_id {
                        return Ok(tok.clone());
                    }
                }
                // The token's `aud` is the rig's ecu_id (its HSM device-key
                // thumbprint), resolved from the device (NOT the roster name), and
                // its `boot_id` is the live boot just read above.
                let ecu_id = fetch_rig_ecu_id(rig_url, *insecure, ca_cert_pem.as_deref()).await?;
                let minted = minter
                    .mint(&ecu_id, &["*".to_string()], Some(&boot_id), *ttl_secs)
                    .await
                    .map_err(|e| EngineError::Internal(format!("mint token: {e}")))?;
                *guard = Some((boot_id, minted.token.clone()));
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

// --- L1 fan-out (the signed plan source) -----------------------------------

/// One part of a component's L2 image, decoded from the L1: the part id (the SUIT
/// component id's second segment), the ciphertext content-address parsed from the
/// L2's `sha256:<hex>` payload uri (the blob to push), and the expected **plaintext
/// image digest** (the SUIT `suit-parameter-image-digest`). That digest is the same
/// currency the vehicle self-reports per installed file (the decrypted, decompressed
/// image's SHA-256), so it drives the copy-forward diff ([`component_unchanged`]).
/// `None` when the L2 carries no image digest for the part (then the component is
/// always pushed full — the safe default).
struct L1Part {
    part: String,
    outer: ContentHash,
    inner: Option<ContentHash>,
}

/// One component's slice of a decoded L1 campaign: the L2 manifest bytes (the
/// engine job's `envelope`) and its parts **in SUIT component order**. The device
/// pairs pushed payloads to manifest components positionally, so that order is
/// load-bearing — preserved here from the manifest's component index.
struct L1Component {
    component: String,
    envelope: Vec<u8>,
    parts: Vec<L1Part>,
}

/// Fan a signed Tower-2 **L1 campaign** out into its per-component L2 slices.
///
/// The L1 wraps one integrated L2 image per component, keyed `#<component>`
/// (`sumo_offboard::CampaignBuilder::add_integrated_image`); each L2 is itself a
/// signed SUIT envelope whose components carry a content-address `sha256:<hex>`
/// payload uri (firmware ciphertext stays in Tower 2's blob store). Decoding is
/// opaque — no device key and no signature check here: the flash engine validates
/// each L2 against the sw-authority anchor at stage time and the device
/// re-validates on-target. Pure (no network), so it unit-tests directly.
fn fanout_l1(l1: &[u8]) -> Result<Vec<L1Component>, Error> {
    let campaign = decode_envelope(l1).map_err(|e| Error::DecodeL1(e.to_string()))?;
    // BTreeMap → deterministic (sorted) component order. Each L2 is an independent
    // job, so cross-component order is immaterial — only within-L2 part order is.
    let mut components = Vec::with_capacity(campaign.integrated_payloads.len());
    for (key, l2) in &campaign.integrated_payloads {
        let component = key.strip_prefix('#').unwrap_or(key).to_string();
        let manifest = Manifest {
            envelope: decode_envelope(l2).map_err(|e| Error::BadL2 {
                component: component.clone(),
                reason: format!("L2 envelope did not decode: {e}"),
            })?,
        };
        let mut parts = Vec::with_capacity(manifest.component_count());
        for i in 0..manifest.component_count() {
            // The SUIT component id is `[component, part]`; the part id is segment 1.
            let part = manifest
                .component_id(i)
                .and_then(|segs| segs.get(1))
                .map(|seg| String::from_utf8_lossy(seg).into_owned())
                .ok_or_else(|| Error::BadL2 {
                    component: component.clone(),
                    reason: format!("component {i} has no part-id segment"),
                })?;
            // The payload uri is the ciphertext content-address (`sha256:<hex>`).
            let uri = manifest.uri(i).ok_or_else(|| Error::BadL2 {
                component: component.clone(),
                reason: format!("part '{part}' has no payload uri"),
            })?;
            let outer = uri.parse::<ContentHash>().map_err(|_| Error::BadL2 {
                component: component.clone(),
                reason: format!("part '{part}' uri '{uri}' is not a content address"),
            })?;
            // The expected plaintext image digest (SUIT image-digest, always
            // SHA-256 here). A non-32-byte or absent digest → `None`, and the
            // component is pushed full (never copy-forwarded on a guess).
            let inner = manifest
                .image_digest(i)
                .and_then(|(d,)| <[u8; 32]>::try_from(d.bytes.as_slice()).ok())
                .map(ContentHash::from_bytes);
            parts.push(L1Part { part, outer, inner });
        }
        components.push(L1Component {
            component,
            envelope: l2.clone(),
            parts,
        });
    }
    Ok(components)
}

/// Where a job's part ciphertext comes from — Tower 2's blob store in production,
/// a fake in tests. A seam so the copy-forward diff (below) can be unit-tested
/// without a live blob store: the manifest-only path fetches nothing at all.
#[async_trait]
trait BlobSource {
    /// Fetch a part's ciphertext by its content-address (`outer`), erroring when
    /// the source has no such blob (a build/publish step out of sync).
    async fn fetch_ciphertext(&self, outer: &ContentHash) -> Result<Vec<u8>, Error>;
}

#[async_trait]
impl BlobSource for SoftwareClient {
    async fn fetch_ciphertext(&self, outer: &ContentHash) -> Result<Vec<u8>, Error> {
        self.get_blob(outer)
            .await?
            .ok_or_else(|| Error::PayloadMissing {
                outer: outer.to_prefixed(),
            })
    }
}

/// Whether the vehicle's active bank already holds **every** part this component's
/// L2 declares — so the push can be manifest-only and the device copy-forwards the
/// content from its own active bank (digest-verified) instead of us re-shipping it.
///
/// Correlation is by the **plaintext image digest**, the content identity itself —
/// verified to be the same currency on both sides: the L2's
/// `suit-parameter-image-digest` and the vehicle's per-file `sha256` are each the
/// SHA-256 of the decrypted, decompressed image. We deliberately do **not** match
/// by part name: the vehicle reports each file under its on-disk *bank filename*, a
/// device-side layout remap of the part-id (e.g. `firmware → rootfs.img`), so a
/// name join would silently never fire for multi-file banks. A digest join is both
/// robust to that remap and exact (equal digest ⇔ equal content).
///
/// UNCHANGED (⇒ manifest-only) iff the vehicle reports this component and every
/// declared part's expected digest is present among the vehicle's current digests
/// for it. Any of: component unknown to the vehicle, a declared part whose content
/// the vehicle lacks, or a part with no expected digest ⇒ CHANGED (push full — the
/// safe default). The device re-derives each copy-forward's target file and
/// re-checks it against the manifest digest on-target, so a copy it cannot satisfy
/// fails safe there rather than installing the wrong bytes.
fn component_unchanged(c: &L1Component, observed: &Tree) -> bool {
    let Some(entity) = observed.entities.get(&c.component) else {
        return false;
    };
    !c.parts.is_empty()
        && c.parts.iter().all(|p| match p.inner {
            Some(inner) => entity.parts.iter().any(|op| op.content == inner),
            None => false,
        })
}

/// Turn decoded L1 components into engine [`FlashJob`]s, diffing each against the
/// vehicle's `observed` state to decide **copy-forward vs full push**:
///
/// - **Unchanged** ([`component_unchanged`]) → a manifest-only job (empty
///   `payloads`, no blob fetched): the device copy-forwards every part from its own
///   active bank, digest-verified against the L2.
/// - **Changed / unknown** → today's behavior: fetch every part's ciphertext from
///   the blob store and push it alongside the manifest.
///
/// The decision is component-level, all-or-nothing: the L2's part order is
/// tower-signed and the device pairs pushed payloads positionally, so we cannot
/// push an arbitrary subset of a component's parts (intra-component part-diff is a
/// follow-up). `only` keeps a single component (the singleshot-in-its-own-
/// transaction path). For a full push, payload order mirrors the manifest's
/// component order and each payload keeps the `#<part>` uri the push wire uses.
/// Every decision is logged so a copy-forward is never a silent skip.
async fn l1_jobs(
    blobs: &impl BlobSource,
    components: Vec<L1Component>,
    observed: &Tree,
    only: Option<&str>,
) -> Result<Vec<FlashJob>, Error> {
    let mut jobs = Vec::new();
    for c in components {
        if only.is_some_and(|o| o != c.component) {
            continue;
        }
        let payloads = if component_unchanged(&c, observed) {
            tracing::info!(
                component = %c.component,
                parts = c.parts.len(),
                "copy-forward: vehicle already carries this component — pushing manifest only (no payloads)"
            );
            Vec::new()
        } else {
            tracing::info!(
                component = %c.component,
                parts = c.parts.len(),
                "push-full: component changed or unknown on the vehicle — shipping all payloads"
            );
            let mut payloads = Vec::with_capacity(c.parts.len());
            for p in &c.parts {
                payloads.push(Payload {
                    uri: format!("#{}", p.part),
                    source: PayloadSource::Bytes(blobs.fetch_ciphertext(&p.outer).await?),
                });
            }
            payloads
        };
        jobs.push(FlashJob {
            component_id: c.component,
            gateway_id: None,
            envelope: c.envelope,
            payloads,
        });
    }
    Ok(jobs)
}

/// The L1 selector: the L1 endpoint resolves a `(channel, device, architecture)`
/// target, so both the device and architecture must be explicit (unlike the
/// single-target channel tree the read-only preview resolves).
fn l1_selector(target: &ChannelTarget) -> Result<(&str, &str), Error> {
    match (target.device.as_deref(), target.architecture.as_deref()) {
        (Some(device), Some(architecture)) => Ok((device, architecture)),
        _ => Err(Error::L1NeedsSelector {
            channel: target.channel.clone(),
        }),
    }
}

/// The shared plan source for the push: read the rig, ask Tower 2 for the signed
/// L1 for this device (relaying the Tower-1 `device_pubkey` and the vehicle's
/// current state), and fan it out into engine [`FlashJob`]s + the sw-authority
/// trust anchor. Also returns the observed tree — the campaign partitions its jobs
/// by the device's per-component update-mode, read here.
#[allow(clippy::too_many_arguments)] // rig + two tower URLs, selector, flag — all distinct
async fn l1_flash_plan(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    only: Option<&str>,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(Vec<FlashJob>, Vec<u8>, Tree), Error> {
    let observed = read_rig_state(rig_url, insecure, ca_cert_pem).await?;
    // The vehicle's self-report flows up as the source of truth (the tower records
    // it; reconciliation stays on the vehicle).
    let current_state =
        serde_json::to_value(&observed).map_err(|e| Error::StateEncode(e.to_string()))?;
    // The relayed Tower-1 identity — the orchestrator hands identity, never a secret.
    let pubkey = device_pubkey(ca_url, device_id).await?;
    let (device, architecture) = l1_selector(target)?;
    let hub = SoftwareClient::new(hub_url);
    // The signed L1 IS the plan: Tower 2 does the diff + per-device assembly and
    // signs the result; the orchestrator relays it, never rebuilds it.
    let l1 = hub
        .channel_target_l1(
            &target.channel,
            device,
            architecture,
            &pubkey,
            device_id,
            Some(&current_state),
            1,
        )
        .await?;
    // Diff each fanned-out component against the vehicle's self-report: unchanged
    // components push manifest-only (device copy-forwards), the rest push full.
    let jobs = l1_jobs(&hub, fanout_l1(&l1)?, &observed, only).await?;
    let trust_anchor = hub.signer_pubkey().await?;
    Ok((jobs, trust_anchor, observed))
}

/// Build the engine [`FlashPlan`] to bring the rig to `target`'s desired state,
/// plus the SUIT trust anchor the engine validates manifests against. Sourced
/// from Tower 2's signed **L1 campaign** for this device ([`l1_flash_plan`]): one
/// signed L2 envelope per component (CEK re-wrapped to the device), whose firmware
/// ciphertext is fetched from Tower 2's blob store and pushed alongside it.
/// Payloads are buffered (`PayloadSource::Bytes`) — fine for the offboard
/// orchestrator; the onboard adapter streams instead.
#[allow(clippy::too_many_arguments)] // rig + two tower URLs, selector, flag — all distinct
pub async fn build_flash_plan(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    only: Option<&str>,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(FlashPlan, Vec<u8>), Error> {
    let (jobs, trust_anchor, _observed) = l1_flash_plan(
        rig_url,
        hub_url,
        ca_url,
        target,
        device_id,
        only,
        insecure,
        ca_cert_pem,
    )
    .await?;
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<FlashResult, Error> {
    let (plan, trust_anchor) = build_flash_plan(
        rig_url,
        hub_url,
        ca_url,
        target,
        device_id,
        only,
        insecure,
        ca_cert_pem,
    )
    .await?;
    // `reboot_to_activate` (the workshop campaign) activates the whole step via one
    // node reboot — both banks boot their new images together, no racy per-VM
    // relaunch. The onboard/field path leaves it false (no orchestrator reboot;
    // activation waits for the next power cycle).
    let engine = FlashEngine::new(
        rig_url,
        Arc::new(token),
        trust_anchor,
        EngineTimeouts::default(),
        insecure,
        ca_cert_pem.map(|c| c.to_vec()),
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

/// Run the rig campaign over the shared engine: fan out Tower 2's signed L1 for
/// the device, group its per-component jobs into ordered steps by update mode
/// (each singleshot alone, the banked group together), and drive
/// [`FlashEngine::run_campaign`] — per step
/// `guard → stage → reset → health (CameUp) → commit | rollback + abort`, on one
/// committed baseline. An unhealthy step rolls back its trial and aborts the chain.
/// `no_commit` leaves healthy banked steps in trial for a manual verdict. Returns
/// each component's final state; an empty result means the L1 carried no
/// components. **Destructive: mutates the rig.**
#[allow(clippy::too_many_arguments)] // rig + two tower URLs, selector, flag, token — all distinct
pub async fn campaign_execute(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    target: &ChannelTarget,
    device_id: &str,
    no_commit: bool,
    token: RigToken,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<Vec<ComponentFlashResult>, Error> {
    // The signed L1 IS the plan: fan it out into per-component jobs once. The
    // observed tree carries each component's update mode — the same source the
    // engine's no-mix guard reads off the device — used to group the jobs.
    let (jobs, trust_anchor, observed) = l1_flash_plan(
        rig_url,
        hub_url,
        ca_url,
        target,
        device_id,
        None,
        insecure,
        ca_cert_pem,
    )
    .await?;
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    // Partition by update mode: singleshot (irreversible, write-through) vs banked
    // (reversible trial). A component the device doesn't classify defaults to
    // banked — the reversible, safe assumption.
    let is_singleshot = |component: &str| {
        observed
            .entities
            .get(component)
            .and_then(|e| e.update_mode.as_ref())
            .map(|m| m.supports_rollback)
            == Some(false)
    };
    let (singleshot, banked): (Vec<FlashJob>, Vec<FlashJob>) = jobs
        .into_iter()
        .partition(|job| is_singleshot(&job.component_id));

    // Ordered steps: each singleshot alone (its own transaction), first — its node
    // reboot must not interrupt a banked trial; then the banked group in ONE step
    // (`force_ecu_reset`: a single coalesced node reboot activates them together).
    let mut steps: Vec<CampaignStep> = singleshot
        .into_iter()
        .map(|job| CampaignStep {
            jobs: vec![job],
            force_ecu_reset: false,
        })
        .collect();
    if !banked.is_empty() {
        steps.push(CampaignStep {
            jobs: banked,
            force_ecu_reset: true,
        });
    }

    // One engine + the rig's (boot-aware) minting token; `run_campaign` varies
    // `force_ecu_reset` per step internally, and the token re-mints across the
    // reboots. `CameUp` is the shared default health gate — the rig's former
    // `step_came_up`, now in the engine.
    let engine = FlashEngine::new(
        rig_url,
        Arc::new(token),
        trust_anchor,
        EngineTimeouts::default(),
        insecure,
        ca_cert_pem.map(|c| c.to_vec()),
    );
    let report = engine.run_campaign(steps, &CameUp, no_commit).await?;
    Ok(report.ecus.iter().map(component_result).collect())
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
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
        insecure,
        ca_cert_pem.map(|c| c.to_vec()),
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<String, Error> {
    let engine = verdict_engine(rig_url, token, false, insecure, ca_cert_pem);
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<String, Error> {
    let engine = verdict_engine(rig_url, token, false, insecure, ca_cert_pem);
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<String, Error> {
    let engine = verdict_engine(rig_url, token, false, insecure, ca_cert_pem);
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<Vec<(String, String)>, Error> {
    let engine = verdict_engine(rig_url, token, true, insecure, ca_cert_pem);
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
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<Vec<(String, String)>, Error> {
    let engine = verdict_engine(rig_url, token, true, insecure, ca_cert_pem);
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
pub async fn flash_commit_trials(
    rig_url: &str,
    token: RigToken,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), Error> {
    verdict_engine(rig_url, token, true, insecure, ca_cert_pem)
        .commit_node_trials()
        .await?;
    Ok(())
}

/// Roll the whole node's in-trial set back in ONE verdict — see [`flash_commit_trials`].
pub async fn flash_rollback_trials(
    rig_url: &str,
    token: RigToken,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), Error> {
    verdict_engine(rig_url, token, true, insecure, ca_cert_pem)
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
fn verdict_engine(
    rig_url: &str,
    token: RigToken,
    force_ecu_reset: bool,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> FlashEngine {
    FlashEngine::new(
        rig_url,
        Arc::new(token),
        Vec::new(),
        EngineTimeouts::default(),
        insecure,
        ca_cert_pem.map(|c| c.to_vec()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use sumo_offboard::cose_key::CoseKey;
    use sumo_offboard::image_builder::{ComponentSpec, MultiComponentBuilder};
    use sumo_offboard::{keygen, CampaignBuilder};

    /// Build one signed L2 image for `component` — a multi-component SUIT envelope
    /// whose parts carry a content-address `sha256:<outer>` payload uri, exactly
    /// the shape Tower 2's `channel_target_l1` emits (encryption elided: the
    /// fan-out reads component-id + uri, never the CEK).
    fn build_l2(key: &CoseKey, component: &str, parts: &[(&str, ContentHash)]) -> Vec<u8> {
        let mut b = MultiComponentBuilder::new()
            .signing_time(1_751_800_000)
            .sequence_number(1);
        for (part, outer) in parts {
            b = b.add_component(ComponentSpec {
                id: vec![component.to_string(), part.to_string()],
                digest: vec![0u8; 32],
                size: 16,
                uri: outer.to_prefixed(),
                encryption_info: None,
            });
        }
        b.build(key).unwrap()
    }

    /// `fanout_l1` decodes the integrated L2s of a signed L1 into per-component
    /// slices, preserving each L2's SUIT component order (load-bearing: the device
    /// pairs pushed payloads to manifest components positionally) and parsing each
    /// `sha256:<hex>` uri back to the blob's outer hash.
    #[test]
    fn fanout_l1_decodes_components_and_ordered_parts() {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let kernel = ContentHash::of(b"vm1-kernel-ciphertext");
        let rootfs = ContentHash::of(b"vm1-rootfs-ciphertext");
        let app = ContentHash::of(b"rt-app-ciphertext");

        let l2_vm1 = build_l2(&key, "vm1", &[("kernel", kernel), ("rootfs", rootfs)]);
        let l2_rt = build_l2(&key, "rt", &[("app", app)]);
        let l1 = CampaignBuilder::new()
            .signing_time(1_751_800_000)
            .sequence_number(1)
            .add_integrated_image("vm1".to_string(), &l2_vm1)
            .add_integrated_image("rt".to_string(), &l2_rt)
            .build(&key)
            .unwrap();

        let fanned = fanout_l1(&l1).unwrap();
        assert_eq!(fanned.len(), 2);
        let by: std::collections::BTreeMap<&str, &L1Component> =
            fanned.iter().map(|c| (c.component.as_str(), c)).collect();

        // The multi-part L2: the job envelope is the L2 bytes verbatim, and its
        // parts stay in manifest order (kernel = component 0, rootfs = component 1).
        let vm1 = by["vm1"];
        assert_eq!(vm1.envelope, l2_vm1);
        let parts: Vec<(&str, ContentHash)> = vm1
            .parts
            .iter()
            .map(|p| (p.part.as_str(), p.outer))
            .collect();
        assert_eq!(parts, vec![("kernel", kernel), ("rootfs", rootfs)]);

        // The single-part L2 (no SET_COMPONENT_INDEX) still resolves its uri.
        let rt = by["rt"];
        assert_eq!(rt.parts.len(), 1);
        assert_eq!(rt.parts[0].part, "app");
        assert_eq!(rt.parts[0].outer, app);
    }

    /// Bytes that aren't a SUIT campaign surface a typed decode error, not a panic.
    #[test]
    fn fanout_l1_rejects_non_campaign_bytes() {
        assert!(matches!(
            fanout_l1(b"not a suit envelope"),
            Err(Error::DecodeL1(_))
        ));
    }

    /// The L1 push path needs an explicit device + architecture (the endpoint
    /// resolves a (channel, device, architecture) target); a bare channel errors.
    #[test]
    fn l1_selector_requires_device_and_architecture() {
        let bare = ChannelTarget::channel("bleeding");
        assert!(matches!(
            l1_selector(&bare),
            Err(Error::L1NeedsSelector { .. })
        ));
        let full = ChannelTarget {
            channel: "bleeding".into(),
            device: Some("rig".into()),
            architecture: Some("arm64".into()),
        };
        assert_eq!(l1_selector(&full).unwrap(), ("rig", "arm64"));
    }

    // --- copy-forward diff ------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A blob source that hands back fixed ciphertext and counts fetches — so a
    /// manifest-only job can be asserted to fetch *nothing*.
    struct FakeBlobs {
        fetches: AtomicUsize,
    }

    impl FakeBlobs {
        fn new() -> Self {
            Self {
                fetches: AtomicUsize::new(0),
            }
        }
        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BlobSource for FakeBlobs {
        async fn fetch_ciphertext(&self, _outer: &ContentHash) -> Result<Vec<u8>, Error> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            Ok(b"ciphertext".to_vec())
        }
    }

    /// Build a signed L1 wrapping one component whose parts carry an explicit
    /// `(part-id, outer, inner)` triple — `inner` becomes the SUIT image-digest the
    /// diff compares, `outer` the blob content-address a full push would fetch.
    fn l1_one_component(
        key: &CoseKey,
        component: &str,
        parts: &[(&str, ContentHash, ContentHash)],
    ) -> Vec<u8> {
        let mut b = MultiComponentBuilder::new()
            .signing_time(1_751_800_000)
            .sequence_number(1);
        for (part, outer, inner) in parts {
            b = b.add_component(ComponentSpec {
                id: vec![component.to_string(), part.to_string()],
                digest: inner.as_bytes().to_vec(),
                size: 16,
                uri: outer.to_prefixed(),
                encryption_info: None,
            });
        }
        let l2 = b.build(key).unwrap();
        CampaignBuilder::new()
            .signing_time(1_751_800_000)
            .sequence_number(1)
            .add_integrated_image(component.to_string(), &l2)
            .build(key)
            .unwrap()
    }

    /// A one-component observed tree: the vehicle reports `parts` as `(file-name,
    /// plaintext-sha256)` — the shape `read_rig_state` builds from the device's
    /// `x-sumo-installed-manifest`.
    fn observed_of(component: &str, parts: &[(&str, ContentHash)]) -> Tree {
        let mut tree = Tree::default();
        tree.entities.insert(
            component.to_string(),
            Entity {
                kind: "vm".to_string(),
                parts: parts
                    .iter()
                    .map(|(name, content)| Part {
                        kind: "file".to_string(),
                        id: name.to_string(),
                        content: *content,
                    })
                    .collect(),
                ..Default::default()
            },
        );
        tree
    }

    /// `fanout_l1` surfaces each part's expected plaintext image-digest (the SUIT
    /// image-digest) alongside the ciphertext content-address.
    #[test]
    fn fanout_l1_surfaces_image_digest() {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let (ok, dk) = (ContentHash::of(b"k-ct"), ContentHash::of(b"k-pt"));
        let l1 = l1_one_component(&key, "vm1", &[("kernel", ok, dk)]);
        let fanned = fanout_l1(&l1).unwrap();
        assert_eq!(fanned[0].parts[0].inner, Some(dk));
        assert_eq!(fanned[0].parts[0].outer, ok);
    }

    /// The diff correlates by digest, so it fires even though the vehicle reports a
    /// part under its remapped on-disk bank filename (`firmware` → `rootfs.img`) —
    /// same content digests ⇒ the component is unchanged.
    #[test]
    fn component_unchanged_matches_by_digest_despite_bank_filename_remap() {
        let (dk, df) = (ContentHash::of(b"kernel-pt"), ContentHash::of(b"rootfs-pt"));
        let c = L1Component {
            component: "vm1".into(),
            envelope: vec![],
            parts: vec![
                L1Part {
                    part: "kernel".into(),
                    outer: ContentHash::of(b"kc"),
                    inner: Some(dk),
                },
                L1Part {
                    part: "firmware".into(),
                    outer: ContentHash::of(b"fc"),
                    inner: Some(df),
                },
            ],
        };
        // Vehicle reports `firmware` under its bank filename `rootfs.img`.
        let observed = observed_of("vm1", &[("kernel", dk), ("rootfs.img", df)]);
        assert!(component_unchanged(&c, &observed));
    }

    /// One differing part ⇒ the whole component is changed (all-or-nothing);
    /// an unknown component or a part the vehicle lacks ⇒ changed; a part with no
    /// expected digest ⇒ changed.
    #[test]
    fn component_unchanged_false_paths() {
        let (dk, df) = (ContentHash::of(b"kernel-pt"), ContentHash::of(b"rootfs-pt"));
        let mk =
            |kernel_inner: Option<ContentHash>, firmware_inner: Option<ContentHash>| L1Component {
                component: "vm1".into(),
                envelope: vec![],
                parts: vec![
                    L1Part {
                        part: "kernel".into(),
                        outer: ContentHash::of(b"kc"),
                        inner: kernel_inner,
                    },
                    L1Part {
                        part: "firmware".into(),
                        outer: ContentHash::of(b"fc"),
                        inner: firmware_inner,
                    },
                ],
            };
        let c = mk(Some(dk), Some(df));

        // A part's content differs on the vehicle.
        let changed = observed_of(
            "vm1",
            &[("kernel", dk), ("rootfs.img", ContentHash::of(b"other"))],
        );
        assert!(!component_unchanged(&c, &changed));

        // The vehicle doesn't report this component at all.
        assert!(!component_unchanged(&c, &Tree::default()));
        assert!(!component_unchanged(
            &c,
            &observed_of("vm2", &[("kernel", dk)])
        ));

        // The vehicle is missing one declared part (only has the kernel).
        let missing = observed_of("vm1", &[("kernel", dk)]);
        assert!(!component_unchanged(&c, &missing));

        // A declared part carries no expected digest — cannot claim unchanged.
        let no_digest = mk(Some(dk), None);
        assert!(!component_unchanged(
            &no_digest,
            &observed_of("vm1", &[("kernel", dk), ("rootfs.img", df)])
        ));
    }

    /// Unchanged component → a manifest-only job: empty payloads, and the blob
    /// store is never touched.
    #[tokio::test]
    async fn l1_jobs_unchanged_component_pushes_manifest_only() {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let (ok, dk) = (ContentHash::of(b"k-ct"), ContentHash::of(b"k-pt"));
        let (of, df) = (ContentHash::of(b"f-ct"), ContentHash::of(b"f-pt"));
        let l1 = l1_one_component(&key, "vm1", &[("kernel", ok, dk), ("firmware", of, df)]);

        // Vehicle already carries both (under the remapped rootfs.img name).
        let observed = observed_of("vm1", &[("kernel", dk), ("rootfs.img", df)]);
        let blobs = FakeBlobs::new();
        let jobs = l1_jobs(&blobs, fanout_l1(&l1).unwrap(), &observed, None)
            .await
            .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].component_id, "vm1");
        assert!(jobs[0].payloads.is_empty(), "manifest-only: no payloads");
        assert!(
            !jobs[0].envelope.is_empty(),
            "the signed L2 is still pushed"
        );
        assert_eq!(blobs.fetches(), 0, "copy-forward fetches no ciphertext");
    }

    /// Changed component → a full job: every declared part's ciphertext is fetched
    /// and pushed (component-level all-or-nothing).
    #[tokio::test]
    async fn l1_jobs_changed_component_pushes_all_payloads() {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let (ok, dk) = (ContentHash::of(b"k-ct"), ContentHash::of(b"k-pt"));
        let (of, df) = (ContentHash::of(b"f-ct"), ContentHash::of(b"f-pt"));
        let l1 = l1_one_component(&key, "vm1", &[("kernel", ok, dk), ("firmware", of, df)]);

        // The rootfs differs — so the whole component ships, both parts.
        let observed = observed_of(
            "vm1",
            &[("kernel", dk), ("rootfs.img", ContentHash::of(b"stale"))],
        );
        let blobs = FakeBlobs::new();
        let jobs = l1_jobs(&blobs, fanout_l1(&l1).unwrap(), &observed, None)
            .await
            .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(
            jobs[0].payloads.len(),
            2,
            "all parts ship, not just the changed one"
        );
        assert_eq!(blobs.fetches(), 2);
    }

    /// A component the vehicle doesn't report (no self-report / brand-new) → full.
    #[tokio::test]
    async fn l1_jobs_unknown_vehicle_pushes_full() {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let (ok, dk) = (ContentHash::of(b"k-ct"), ContentHash::of(b"k-pt"));
        let l1 = l1_one_component(&key, "vm1", &[("kernel", ok, dk)]);

        let blobs = FakeBlobs::new();
        let jobs = l1_jobs(&blobs, fanout_l1(&l1).unwrap(), &Tree::default(), None)
            .await
            .unwrap();

        assert_eq!(jobs[0].payloads.len(), 1);
        assert_eq!(blobs.fetches(), 1);
    }
}
