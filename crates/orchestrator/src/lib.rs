//! sumo-provision orchestrator core.
//!
//! The orchestrator is the only component that talks to both the towers and a
//! rig. Today it can *observe* a rig over SOVD ([`read_rig_state`]) using the
//! `sovd-client` library; fetching from Tower 2, minting from Tower 1, and
//! flashing over the SOVD `/updates` wire land against the roadmap in
//! `architecture.md`.

use serde::Deserialize;
use sovd_client::{SovdClient, SovdClientError};

/// SOVD data resource carrying each VM's signed installed inventory (the
/// running bank's IVD manifest). Vendor id, read over the standard `/data` path.
const INSTALLED_MANIFEST: &str = "x-sumo-installed-manifest";

/// Error from the orchestrator.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sovd error: {0}")]
    Sovd(#[from] SovdClientError),
    #[error("could not parse installed manifest for {component}: {source}")]
    Manifest {
        component: String,
        source: serde_json::Error,
    },
}

/// The observed state of a rig — the input to the twin / diff. Read from the
/// rig over SOVD; the rig is the source of truth.
#[derive(Debug, Clone)]
pub struct RigState {
    pub components: Vec<ComponentState>,
}

/// One component's observed state.
#[derive(Debug, Clone)]
pub struct ComponentState {
    pub id: String,
    pub name: String,
    pub kind: String,
    /// The signed installed inventory, if the component has a committed bank
    /// (`None` = never flashed / no signed manifest).
    pub installed: Option<InstalledManifest>,
}

/// A VM's installed inventory, from `x-sumo-installed-manifest` (the running
/// bank's signed IVD manifest). Read-and-display for now; independent signature
/// verification + channel diff land with the twin step.
#[derive(Debug, Clone, Deserialize)]
pub struct InstalledManifest {
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub files: Vec<InstalledFile>,
}

/// The IVD identity block (a projection — only the fields we surface today).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Identity {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

/// One installed file and its content hash (the twin's observed inner-hash).
#[derive(Debug, Clone, Deserialize)]
pub struct InstalledFile {
    pub path: String,
    pub sha256: String,
}

/// Read a rig's observed state over SOVD: its components and, for each VM, the
/// signed installed inventory (`x-sumo-installed-manifest`).
pub async fn read_rig_state(sovd_url: &str) -> Result<RigState, Error> {
    let client = SovdClient::new(sovd_url)?;
    let mut components = Vec::new();
    for c in client.list_components().await? {
        let installed = read_installed(&client, &c.id).await?;
        components.push(ComponentState {
            id: c.id,
            name: c.name,
            kind: c.component_type.unwrap_or_default(),
            installed,
        });
    }
    Ok(RigState { components })
}

/// Read one component's installed manifest; `None` on 404 (never flashed).
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
        Err(SovdClientError::ServerError { status: 404, .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
