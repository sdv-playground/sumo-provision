//! sumo-provision orchestrator core.
//!
//! The orchestrator is the only component that talks to both the towers and a
//! rig. It observes a rig over SOVD as a [`wire::Tree`] ([`read_rig_state`]),
//! which [`wire::diff`] / [`wire::flash_plan`] compare against a desired tree (a
//! channel). [`apply_plan`] resolves a channel's ship-set against Tower 2 — the
//! read/resolve half of apply. Minting from Tower 1 and driving the SOVD
//! `/updates` flash land against the roadmap in `architecture.md`.

use client::{ClientError, IdentityClient, SoftwareClient};
use serde::{Deserialize, Serialize};
use sovd_client::{SovdClient, SovdClientError};
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

/// Plan how to bring the rig at `rig_url` to the desired state on `channel`
/// (resolved from Tower 2 at `hub_url`). Reads the rig over SOVD, resolves the
/// channel's desired tree, computes the per-component [`wire::flash_plan`], and
/// resolves each shipped part against Tower 2's index — confirming Tower 2 can
/// actually serve it and totalling the transfer. This is the read/resolve half
/// of apply; flashing drives the SOVD `/updates` wire per component from it.
pub async fn apply_plan(rig_url: &str, hub_url: &str, channel: &str) -> Result<ApplyPlan, Error> {
    let observed = read_rig_state(rig_url).await?;
    let hub = SoftwareClient::new(hub_url);
    let desired = hub
        .channel_tree(channel)
        .await?
        .ok_or_else(|| Error::ChannelNotFound {
            channel: channel.to_string(),
        })?;
    guard_update_modes(&observed, &desired)?;
    let plan = wire::flash_plan(&observed, &desired);

    let mut components = Vec::new();
    for (path, entity) in &desired.entities {
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
            });
        }
    }
    Ok(ApplyPlan {
        channel: channel.to_string(),
        components,
    })
}

/// Reject a campaign that mixes rollbackable (banked) and irreversible
/// (singleshot, e.g. the HSM keystore) components — a rollback would leave the
/// device undefined. Uses the twin's reported `x-sumo-update-mode`; components
/// the device doesn't report (`None`) are skipped (graceful on older firmware).
fn guard_update_modes(observed: &Tree, desired: &Tree) -> Result<(), Error> {
    let mut rollbackable = Vec::new();
    let mut irreversible = Vec::new();
    for path in desired.entities.keys() {
        if let Some(m) = observed
            .entities
            .get(path)
            .and_then(|e| e.update_mode.as_ref())
        {
            if m.supports_rollback {
                rollbackable.push(path.clone());
            } else {
                irreversible.push(path.clone());
            }
        }
    }
    if !rollbackable.is_empty() && !irreversible.is_empty() {
        return Err(Error::MixedUpdateModes {
            rollbackable,
            irreversible,
        });
    }
    Ok(())
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

/// Assemble the per-device flash bundle to bring the rig to `channel`'s desired
/// state: the ship-set ([`apply_plan`]), then a signed SUIT envelope per
/// component (built by Tower 2, with the CEK re-wrapped to the device's Tower 1
/// key) plus its payload references — exactly what the flash would upload over
/// SOVD, assembled without touching the rig.
pub async fn flash_bundle(
    rig_url: &str,
    hub_url: &str,
    ca_url: &str,
    channel: &str,
    device_id: &str,
) -> Result<FlashBundle, Error> {
    let plan = apply_plan(rig_url, hub_url, channel).await?;

    let device = IdentityClient::new(ca_url)
        .get_device(device_id)
        .await?
        .ok_or_else(|| Error::DeviceNotFound {
            id: device_id.to_string(),
        })?;
    let pubkey = device.pubkey.ok_or_else(|| Error::DeviceNoPubkey {
        id: device_id.to_string(),
    })?;

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
        channel: channel.to_string(),
        device: device_id.to_string(),
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(rollback: bool) -> Entity {
        Entity {
            update_mode: Some(UpdateMode {
                mode: if rollback { "banked" } else { "singleshot" }.into(),
                supports_rollback: rollback,
                dual_bank: rollback,
                reset_kind: "local".into(),
            }),
            ..Default::default()
        }
    }
    fn tree(entries: Vec<(&str, Entity)>) -> Tree {
        Tree {
            entities: entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }
    fn desired(paths: &[&str]) -> Tree {
        tree(paths.iter().map(|p| (*p, Entity::default())).collect())
    }

    #[test]
    fn guard_rejects_rollbackable_mixed_with_irreversible() {
        let observed = tree(vec![("vm1", mode(true)), ("hsm", mode(false))]);
        assert!(matches!(
            guard_update_modes(&observed, &desired(&["vm1", "hsm"])),
            Err(Error::MixedUpdateModes { .. })
        ));
    }

    #[test]
    fn guard_allows_all_rollbackable() {
        let observed = tree(vec![("vm1", mode(true)), ("vm2", mode(true))]);
        assert!(guard_update_modes(&observed, &desired(&["vm1", "vm2"])).is_ok());
    }

    #[test]
    fn guard_allows_irreversible_alone() {
        let observed = tree(vec![("hsm", mode(false))]);
        assert!(guard_update_modes(&observed, &desired(&["hsm"])).is_ok());
    }

    #[test]
    fn guard_skips_components_with_unknown_mode() {
        // hsm reports no mode (older firmware) → not counted, so no mix is seen.
        let observed = tree(vec![("vm1", mode(true)), ("hsm", Entity::default())]);
        assert!(guard_update_modes(&observed, &desired(&["vm1", "hsm"])).is_ok());
    }
}
