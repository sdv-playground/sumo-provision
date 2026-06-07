//! Shared wire types for sumo-provision.
//!
//! Content addressing ([`ContentHash`], [`ArtifactRef`]) plus the **vehicle
//! model** — a tree of [`Entity`]s, each holding content-hashed [`Part`]s — and
//! the [`diff`] that compares an observed tree (read from a rig) against a
//! desired one (a release). Deliberately dependency-light (serde + hashing) and
//! schema-agnostic: `kind`s are open strings, so the engine never hardcodes any
//! fleet's component types.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A SHA-256 content address.
///
/// Everything sumo-provision stores or references is addressed by one of these:
/// blobs by their ciphertext hash (the *outer* hash), plaintext software
/// identity by the *inner* hash, manifests by their own hash. On the wire and
/// in URLs it renders as `sha256:<hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Compute the SHA-256 of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&digest);
        Self(buf)
    }

    /// The raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render as `sha256:<hex>` — the canonical form on the wire and in URLs.
    pub fn to_prefixed(&self) -> String {
        format!("sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_prefixed())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_prefixed())
    }
}

impl FromStr for ContentHash {
    type Err = ParseHashError;

    /// Accepts either `sha256:<hex>` (preferred) or a bare 64-char hex string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_part = s.strip_prefix("sha256:").unwrap_or(s);
        let bytes = hex::decode(hex_part).map_err(|_| ParseHashError::NotHex)?;
        let buf: [u8; 32] = bytes.try_into().map_err(|_| ParseHashError::WrongLength)?;
        Ok(Self(buf))
    }
}

impl TryFrom<String> for ContentHash {
    type Error = ParseHashError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<ContentHash> for String {
    fn from(h: ContentHash) -> String {
        h.to_prefixed()
    }
}

/// Error parsing a [`ContentHash`] from text.
#[derive(Debug, thiserror::Error)]
pub enum ParseHashError {
    #[error("content hash is not valid hex")]
    NotHex,
    #[error("content hash must be 32 bytes (64 hex chars)")]
    WrongLength,
}

/// A published artifact's content identity.
///
/// `inner` addresses the plaintext — the device-independent software identity
/// used for secure boot and the twin diff. `outer` addresses the ciphertext
/// blob in the object store. The content-encryption key lives only in Tower 2's
/// index, never here.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub inner: ContentHash,
    pub outer: ContentHash,
    pub size: u64,
}

// --- vehicle model ---------------------------------------------------------

/// One updatable unit on an [`Entity`]: a logical id + a content hash, of some
/// open `kind`. Files in a bank, container images, and parameterization blobs
/// are all Parts — everything updatable is "a logical id with a content hash".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// Open kind, e.g. `"file"`, `"oci-image"`, `"param-blob"`.
    pub kind: String,
    /// Logical id within the entity, e.g. `"kernel"` or `"image"`.
    pub id: String,
    /// The content hash — the observed / desired inner-hash.
    pub content: ContentHash,
}

/// A node in the vehicle tree and the [`Part`]s installed on it. The tree's
/// shape is carried by the path keys in [`Tree`]; this is the per-node payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// Open kind, e.g. `"vehicle"`, `"vm"`, `"sovd-server"`, `"container"`.
    #[serde(default)]
    pub kind: String,
    /// Human-readable version label — display only; the [`diff`] ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The updatable units on this entity.
    #[serde(default)]
    pub parts: Vec<Part>,
}

/// A vehicle's state as a flat tree keyed by entity path (`"vm1"`,
/// `"vm1/sovd/myapp"`); the hierarchy is encoded in the paths (the parent of
/// `"a/b/c"` is `"a/b"`). Used for both the observed state (read from a rig) and
/// the desired state (a release).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    pub entities: BTreeMap<String, Entity>,
}

/// The kind of change a [`diff`] found for a part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    Added,
    Removed,
    Changed,
}

/// One part-level change between two trees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartChange {
    pub entity: String,
    pub change: Change,
    pub part: String,
    pub kind: String,
}

/// The difference between an observed tree and a desired tree — what an update
/// would touch to bring observed up to desired.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeDiff {
    /// Entities in desired but not observed (e.g. a new container).
    pub entities_added: Vec<String>,
    /// Entities observed but not in desired (e.g. a retired ECU).
    pub entities_removed: Vec<String>,
    /// Part-level changes (added / changed / removed).
    pub parts: Vec<PartChange>,
}

impl TreeDiff {
    /// True when observed already matches desired — nothing to flash.
    pub fn is_empty(&self) -> bool {
        self.entities_added.is_empty() && self.entities_removed.is_empty() && self.parts.is_empty()
    }
}

/// Diff `observed` against `desired`: the changes that would bring `observed`
/// up to `desired`. Pure and schema-agnostic — entities compared by path, parts
/// by `(id, content hash)`.
pub fn diff(observed: &Tree, desired: &Tree) -> TreeDiff {
    let mut out = TreeDiff::default();
    let empty = Entity::default();

    // Every desired entity: structural add if new, then a part diff vs observed.
    for (path, des) in &desired.entities {
        if !observed.entities.contains_key(path) {
            out.entities_added.push(path.clone());
        }
        let obs = observed.entities.get(path).unwrap_or(&empty);
        diff_parts(path, &obs.parts, &des.parts, &mut out.parts);
    }
    // Observed entities not desired: structural remove + all parts removed.
    for (path, obs) in &observed.entities {
        if !desired.entities.contains_key(path) {
            out.entities_removed.push(path.clone());
            diff_parts(path, &obs.parts, &[], &mut out.parts);
        }
    }
    out
}

fn diff_parts(entity: &str, observed: &[Part], desired: &[Part], out: &mut Vec<PartChange>) {
    let obs: BTreeMap<&str, &Part> = observed.iter().map(|p| (p.id.as_str(), p)).collect();
    let des_ids: BTreeSet<&str> = desired.iter().map(|p| p.id.as_str()).collect();
    let change = |c, p: &Part| PartChange {
        entity: entity.to_string(),
        change: c,
        part: p.id.clone(),
        kind: p.kind.clone(),
    };
    for dp in desired {
        match obs.get(dp.id.as_str()) {
            None => out.push(change(Change::Added, dp)),
            Some(op) if op.content != dp.content => out.push(change(Change::Changed, dp)),
            Some(_) => {}
        }
    }
    for op in observed {
        if !des_ids.contains(op.id.as_str()) {
            out.push(change(Change::Removed, op));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_prefixed_and_bare() {
        let h = ContentHash::of(b"hello sumo");
        let prefixed = h.to_prefixed();
        assert!(prefixed.starts_with("sha256:"));
        assert_eq!(prefixed.parse::<ContentHash>().unwrap(), h);

        let bare = &prefixed["sha256:".len()..];
        assert_eq!(bare.parse::<ContentHash>().unwrap(), h);
    }

    #[test]
    fn rejects_bad_input() {
        assert!("sha256:zz".parse::<ContentHash>().is_err()); // not hex
        assert!("sha256:abcd".parse::<ContentHash>().is_err()); // too short
    }

    #[test]
    fn serde_roundtrip() {
        let h = ContentHash::of(b"abc");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", h.to_prefixed()));
        let back: ContentHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;

    fn part(kind: &str, id: &str, seed: &[u8]) -> Part {
        Part {
            kind: kind.into(),
            id: id.into(),
            content: ContentHash::of(seed),
        }
    }
    fn entity(kind: &str, parts: Vec<Part>) -> Entity {
        Entity {
            kind: kind.into(),
            version: None,
            parts,
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

    #[test]
    fn identical_trees_have_no_diff() {
        let t = tree(vec![(
            "vm1",
            entity("vm", vec![part("file", "kernel", b"k")]),
        )]);
        assert!(diff(&t, &t).is_empty());
    }

    #[test]
    fn detects_added_changed_removed_parts() {
        let observed = tree(vec![(
            "vm1",
            entity(
                "vm",
                vec![part("file", "kernel", b"k1"), part("file", "rootfs", b"r")],
            ),
        )]);
        let desired = tree(vec![(
            "vm1",
            entity(
                "vm",
                vec![part("file", "kernel", b"k2"), part("file", "policy", b"p")],
            ),
        )]);
        let d = diff(&observed, &desired);
        assert!(d.entities_added.is_empty() && d.entities_removed.is_empty());
        let mut got: Vec<(&str, Change)> = d
            .parts
            .iter()
            .map(|c| (c.part.as_str(), c.change))
            .collect();
        got.sort_by_key(|(name, _)| *name);
        assert_eq!(
            got,
            vec![
                ("kernel", Change::Changed),
                ("policy", Change::Added),
                ("rootfs", Change::Removed),
            ]
        );
    }

    #[test]
    fn detects_entity_add_remove() {
        let observed = tree(vec![("vm1", entity("vm", vec![]))]);
        let desired = tree(vec![(
            "vm1/sovd/app",
            entity("container", vec![part("oci-image", "image", b"img")]),
        )]);
        let d = diff(&observed, &desired);
        assert_eq!(d.entities_added, vec!["vm1/sovd/app"]);
        assert_eq!(d.entities_removed, vec!["vm1"]);
        assert_eq!(d.parts.len(), 1);
        assert_eq!(d.parts[0].change, Change::Added);
        assert_eq!(d.parts[0].entity, "vm1/sovd/app");
    }

    #[test]
    fn release_json_roundtrips() {
        let t = tree(vec![(
            "vehicle",
            entity("vehicle", vec![part("param-blob", "params", b"cfg")]),
        )]);
        let json = serde_json::to_string(&t).unwrap();
        let back: Tree = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}
