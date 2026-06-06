//! Shared wire types for sumo-provision.
//!
//! This crate holds the data structures exchanged between the towers, the
//! orchestrator, and rigs: content hashes, and (as they land) manifests,
//! channel pointers, and the digital twin. It is deliberately dependency-light
//! (serde + hashing only) so any component can link it.
//!
//! [`ContentHash`] and [`ArtifactRef`] exist today; the manifest / channel /
//! twin types land later — see `architecture.md`, roadmap.

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
