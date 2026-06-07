//! The sw-authority signer (Tower 2 is the single software signer).
//!
//! Builds per-device, signed, encrypted SUIT envelopes from stored content,
//! reusing `sumo-offboard` so we don't fork the envelope format. Content is
//! encrypted once (see [`crate::crypto`]); here the stored CEK is re-wrapped to
//! each device's key (`rewrap_cek_ecdh`, no re-encryption) and the per-device
//! manifest is signed with the sw-authority key.
//!
//! The struct is exercised end-to-end by the test below; it is wired into a
//! `POST /admin/envelope` endpoint in the next slice.
#![allow(dead_code)]

use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::image_builder::{ComponentSpec, MultiComponentBuilder};
use sumo_offboard::recipient::Recipient;
use sumo_offboard::{encryptor, keygen, OffboardError};

/// The sw-authority signing key (COSE ES256).
pub struct Signer {
    key: CoseKey,
}

/// One part to place in a device's envelope: its plaintext identity + the
/// stored CEK/IV (from the artifact index) so the CEK can be re-wrapped.
pub struct EnvelopePart {
    /// Part id (the SUIT component id segment and `#uri`), e.g. `"kernel"`.
    pub id: String,
    /// SHA-256 of the **plaintext** — the SUIT image digest (our inner hash).
    pub inner: [u8; 32],
    /// Plaintext size.
    pub size: u64,
    /// The content-encryption key from the index (AES-128).
    pub cek: [u8; 16],
    /// The GCM IV from the index.
    pub iv: [u8; 12],
}

impl Signer {
    /// Generate a fresh sw-authority key.
    pub fn generate() -> Result<Self, OffboardError> {
        Ok(Self {
            key: keygen::generate_signing_key(keygen::ES256)?,
        })
    }

    /// Load the sw-authority key from COSE_Key CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, OffboardError> {
        Ok(Self {
            key: CoseKey::from_cose_key_bytes(bytes)?,
        })
    }

    /// Serialize the (private) key as COSE_Key CBOR — for persistence.
    pub fn to_cbor(&self) -> Vec<u8> {
        self.key.to_cose_key_bytes()
    }

    /// The public trust anchor (COSE_Key CBOR) the rig pins to verify envelopes.
    pub fn public_key_cbor(&self) -> Vec<u8> {
        self.key.public_key_bytes()
    }

    /// Build a signed SUIT envelope for one component's `parts`, with each part's
    /// CEK re-wrapped to `device_pubkey` (the device's COSE_Key CBOR). The
    /// ciphertext is untouched — the device fetches it by `#<part>` and decrypts
    /// with the re-wrapped CEK.
    pub fn build_envelope(
        &self,
        device_pubkey: &[u8],
        device_kid: &[u8],
        component: &str,
        parts: &[EnvelopePart],
        seq: u64,
    ) -> Result<Vec<u8>, OffboardError> {
        let recipient = Recipient {
            public_key: CoseKey::from_cose_key_bytes(device_pubkey)?,
            kid: device_kid.to_vec(),
        };
        let mut builder = MultiComponentBuilder::new().sequence_number(seq);
        for p in parts {
            let enc_info = encryptor::rewrap_cek_ecdh(&p.cek, &p.iv, &recipient)?;
            builder = builder.add_component(ComponentSpec {
                id: vec![component.to_string(), p.id.clone()],
                digest: p.inner.to_vec(),
                size: p.size,
                uri: format!("#{}", p.id),
                encryption_info: Some(enc_info),
            });
        }
        builder.build(&self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CborSerializable;
    use sumo_crypto::RustCryptoBackend;
    use sumo_onboard::decryptor::{InMemoryKeyUnwrap, StreamingDecryptor};
    use sumo_onboard::validator::Validator;

    /// The whole signer path: encrypt-once → re-wrap the CEK to a device →
    /// multi-component signed manifest → the device validates the sw-authority
    /// signature and decrypts with its own key, recovering the plaintext.
    #[test]
    fn encrypt_once_rewrap_build_validate_decrypt() {
        let crypto = RustCryptoBackend::new();
        let signer = Signer::generate().unwrap();
        let device = keygen::generate_device_key(keygen::ES256).unwrap();

        let pt = b"vm1 kernel plaintext for the per-device envelope roundtrip";

        // What Tower 2's content store does: encrypt once, keep CEK + IV.
        let enc = encryptor::encrypt_firmware(pt, &[]).unwrap();
        let iv = encryptor::extract_iv_from_enc_info(&enc.encryption_info).unwrap();
        let part = EnvelopePart {
            id: "kernel".into(),
            inner: encryptor::sha256(pt),
            size: pt.len() as u64,
            cek: enc.cek,
            iv,
        };

        // Tower 2 builds the per-device envelope (only the device's PUBLIC key).
        let envelope = signer
            .build_envelope(
                &device.public_key_bytes(),
                b"managed-cvc",
                "vm1",
                &[part],
                1,
            )
            .unwrap();

        // Device side: validate the sw-authority signature, then decrypt.
        let mut validator = Validator::new(&signer.public_key_cbor(), None);
        validator
            .add_device_key(&device.to_cose_key_bytes())
            .unwrap();
        let manifest = validator.validate_envelope(&envelope, &crypto, 0).unwrap();

        let device_coset = coset::CoseKey::from_slice(&device.to_cose_key_bytes()).unwrap();
        let unwrap = InMemoryKeyUnwrap::new(&device_coset, &crypto);
        let mut decryptor = StreamingDecryptor::new(&manifest, 0, &unwrap, &crypto).unwrap();
        let mut out = vec![0u8; enc.ciphertext.len() + 256];
        let mut total = 0;
        total += decryptor
            .update(&enc.ciphertext, &mut out[total..])
            .unwrap();
        total += decryptor.finalize(&mut out[total..]).unwrap();
        assert_eq!(&out[..total], pt);
    }
}
