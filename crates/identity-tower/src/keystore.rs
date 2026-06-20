//! Native HSM trust-anchor keystore minting — Tower 1 builds the factory
//! keystore SUIT in-process (mirroring sumo-mm's `build_hsm_keys` example),
//! using the shared `hsm` schema + the `sumo-offboard` SUIT toolkit. The
//! keystore enumerates the device's key slots and carries the trust anchors
//! (public halves only — never a private key): `sw-authority` = Tower 2's
//! signer, `key-authority` = this CA. Signed with the well-known factory key
//! (scalar=1) so a factory-fresh HSM accepts the very first install.

use anyhow::anyhow;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use coset::iana;
use coset::CborSerializable;
use hsm::payload::{
    self, HsmKeystore, KeySlot, LeafCert, TrustAnchorCert, DELEGATION_ROOT_ANCHOR_ID,
    FACTORY_SIGNING_PUBLIC, FACTORY_SIGNING_SCALAR, KEY_TYPE_AES_256, KEY_TYPE_EC_P256, OP_DECRYPT,
    OP_ENCRYPT, OP_GET_PUBKEY, OP_SIGN, OP_VERIFY,
};
use hsm::{KeyRole, KeyType};
use serde::Deserialize;
use sqlx::Row;
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::recipient::Recipient;
use sumo_offboard::{encryptor, keygen, ImageManifestBuilder};

use crate::devices::{AppError, AppState};

/// `POST /admin/devices/{id}/keystore` request.
#[derive(Deserialize)]
pub struct MintKeystoreReq {
    /// Tower 2's signer public key (the `sw-authority` trust anchor), hex of the
    /// COSE_Key CBOR — `GET {hub}/admin/signer/pubkey`. Passed in so Tower 1
    /// stays software-blind.
    pub sw_authority_pubkey: String,
    /// Anti-rollback floor for the keystore (and the envelope sequence number).
    #[serde(default = "default_security_version")]
    pub security_version: u64,
}

fn default_security_version() -> u64 {
    1
}

/// `POST /admin/devices/{id}/keystore` — mint the factory HSM trust-anchor
/// keystore SUIT for a registered device and return it (`application/cbor`). The
/// device-decrypt recipient is the device's stored pubkey (hex COSE_Key).
pub async fn mint_keystore_endpoint(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<MintKeystoreReq>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query("SELECT pubkey FROM devices WHERE id = $1")
        .bind(&id)
        .fetch_optional(&s.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let pubkey_hex: String = row
        .and_then(|r| r.get::<Option<String>, _>("pubkey"))
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "device '{id}' has no registered pubkey — register/enroll it first"
            ))
        })?;
    let device_decrypt_cose = hex::decode(pubkey_hex.trim())
        .map_err(|_| AppError::BadRequest("device pubkey is not hex".into()))?;
    let sw_authority_cose = hex::decode(req.sw_authority_pubkey.trim())
        .map_err(|_| AppError::BadRequest("sw_authority_pubkey is not hex".into()))?;
    let ka_sec1 = s
        .key_authority_ca
        .public_sec1()
        .map_err(AppError::Internal)?;
    // The delegation root (DER) — the CA the device pins to accept a delegated
    // (x5c) operator token. Provisioned in the keystore so it reaches the HSM by
    // normal T1 provisioning, not an out-of-band file. Its own trust domain,
    // distinct from key-authority / identity / sw-authority.
    let delegation_root_der = s
        .delegation_ca
        .root_cert_der()
        .map_err(AppError::Internal)?;

    // The device's tls-identity leaf, if it's been enrolled — delivered in the
    // keystore envelope (schema v3) so the cross-node mTLS listener finds its
    // cert. `None` until the device enrolls its tls-identity CSR (a re-provision
    // after first boot then carries the leaf).
    let tls_leaf: Option<Vec<u8>> = sqlx::query(
        "SELECT cert_der FROM device_certs WHERE device_id = $1 AND key_id = 'tls-identity'",
    )
    .bind(&id)
    .fetch_optional(&s.pool)
    .await
    .map_err(|e| AppError::Internal(e.into()))?
    .map(|r| r.get::<Vec<u8>, _>("cert_der"));

    let suit = mint_keystore(
        &device_decrypt_cose,
        &sw_authority_cose,
        &ka_sec1,
        req.security_version,
        tls_leaf.as_deref(),
        &delegation_root_der,
    )
    .map_err(AppError::Internal)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        suit,
    ))
}

/// Build the in-memory keystore (slots + any leaf certs) the envelope carries.
/// Split out from [`mint_keystore`] so the slot/cert shaping is unit-testable
/// without the SUIT encrypt/sign machinery.
///
/// `tls_identity_leaf` (DER), when present, is attached as the signed leaf for
/// the device's `tls-identity` slot — a public artifact, inert without the HSM
/// private key, delivered on the one keystore channel (schema v3). It's `None`
/// on first provision; the orchestrator supplies it on re-provision once the
/// device's `tls-identity` CSR has been enrolled.
///
/// `delegation_root_der` (DER) is the delegation CA root, embedded as a pinned
/// `trust_anchors` entry — the root a delegated operator token's `x5c` chain must
/// validate to, provisioned into the HSM rather than an out-of-band file.
fn assemble_keystore(
    sw_authority_sec1: &[u8; 65],
    key_authority_pub_sec1: &[u8; 65],
    security_version: u64,
    tls_identity_leaf: Option<&[u8]>,
    delegation_root_der: &[u8],
) -> HsmKeystore {
    // Slots are driven by the canonical mandatory role set (the device wire
    // contract). Trust anchors carry a public key; device-generated slots carry
    // none (the HSM creates those keypairs locally during provisioning).
    let mut slots = Vec::with_capacity(KeyRole::mandatory_roles().len());
    for &role in KeyRole::mandatory_roles() {
        let anchor_public_key: Option<Vec<u8>> = if role.is_device_generated() {
            None
        } else {
            Some(match role {
                KeyRole::SoftwareAuthority => sw_authority_sec1.to_vec(),
                // Dev HC issuer = the well-known factory key (scalar=1, public):
                // any dev tooling can mint a FactoryReset token, so a dev rig is
                // always resettable even if Tower 1's storage is lost. Production
                // swaps in the real Tower-1/OEM HC root here (then key-escrowed).
                // See docs/design/authorization.md §6.
                KeyRole::ResetIssuer => FACTORY_SIGNING_PUBLIC.to_vec(),
                // key-authority + platform/application/operational-issuer default
                // to this CA's key for the dev flow; only firmware (sw-authority)
                // is load-bearing here. Add distinct anchors when those tiers go live.
                _ => key_authority_pub_sec1.to_vec(),
            })
        };
        // The lone AES slot (storage-key) is symmetric: KEY_TYPE_AES_256,
        // ENCRYPT/DECRYPT, never a public-key op. Every other slot is EC-P256.
        let is_aes = role.key_type() == KeyType::Aes256;
        let allowed_ops = if anchor_public_key.is_some() {
            Some(vec![OP_VERIFY, OP_GET_PUBKEY])
        } else if is_aes {
            Some(vec![OP_ENCRYPT, OP_DECRYPT])
        } else {
            Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY])
        };
        slots.push(KeySlot {
            key_id: role.key_id().to_string(),
            key_kind: if is_aes { KEY_TYPE_AES_256 } else { KEY_TYPE_EC_P256 },
            anchor_public_key,
            allowed_guests: None,
            allowed_ops,
        });
    }

    let mut certificates = Vec::new();
    if let Some(leaf) = tls_identity_leaf {
        certificates.push(LeafCert {
            key_id: KeyRole::TlsIdentity.key_id().to_string(),
            certificate: leaf.to_vec(),
        });
    }

    // The delegation root — the CA the device pins to accept a delegated (x5c)
    // operator token. A foreign CA root (its own trust domain), so it rides the
    // dedicated `trust_anchors` channel, NOT `certificates` (device-key leaves).
    let trust_anchors = vec![TrustAnchorCert {
        anchor_id: DELEGATION_ROOT_ANCHOR_ID.to_string(),
        certificate: delegation_root_der.to_vec(),
    }];

    HsmKeystore {
        schema_version: payload::SCHEMA_VERSION,
        security_version,
        identities: Vec::new(),
        slots,
        certificates,
        trust_anchors,
    }
}

/// Mint the factory HSM trust-anchor keystore as a signed + encrypted SUIT
/// envelope (component `["hsm","keys"]`, integrated `#hsm-keys` payload).
///
/// - `device_decrypt_cose`    — device decrypt pubkey, COSE_Key CBOR (ECDH recipient).
/// - `sw_authority_cose`      — Tower 2 signer pubkey, COSE_Key CBOR (sw-authority anchor).
/// - `key_authority_pub_sec1` — this CA's pubkey, SEC1 (key-authority anchor).
/// - `security_version`       — anti-rollback floor / SUIT sequence number.
/// - `tls_identity_leaf`      — the device's signed `tls-identity` leaf (DER), or `None`.
/// - `delegation_root_der`    — the delegation CA root (DER), pinned by the device
///                              as the delegated-token trust anchor.
pub fn mint_keystore(
    device_decrypt_cose: &[u8],
    sw_authority_cose: &[u8],
    key_authority_pub_sec1: &[u8; 65],
    security_version: u64,
    tls_identity_leaf: Option<&[u8]>,
    delegation_root_der: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let sw_authority_sec1 = cose_to_sec1(sw_authority_cose)?;
    let keystore = assemble_keystore(
        &sw_authority_sec1,
        key_authority_pub_sec1,
        security_version,
        tls_identity_leaf,
        delegation_root_der,
    );
    let cbor = payload::encode(&keystore).map_err(|e| anyhow!("encode HSM keystore: {e}"))?;
    // The SUIT image digest/size describe the PLAINTEXT keystore CBOR (what the
    // device recovers after decrypt + decompress).
    let plaintext_digest = encryptor::sha256(&cbor);

    let compressed =
        encryptor::compress_firmware(&cbor, 3, None).map_err(|e| anyhow!("compress: {e}"))?;
    let recipient = Recipient {
        public_key: CoseKey::from_cose_key_bytes(device_decrypt_cose)
            .map_err(|e| anyhow!("device decrypt key is not a COSE_Key: {e}"))?,
        kid: KeyRole::DeviceDecryption.key_id().as_bytes().to_vec(),
    };
    let ephemeral = keygen::generate_device_key(keygen::ES256)
        .map_err(|e| anyhow!("ephemeral sender key: {e}"))?;
    let encrypted = encryptor::encrypt_firmware_ecdh(&compressed, &ephemeral, &[recipient])
        .map_err(|e| anyhow!("ECDH-encrypt keystore: {e}"))?;

    let factory_key = factory_signing_key()?;
    ImageManifestBuilder::new()
        .component_id(vec!["hsm".to_string(), "keys".to_string()])
        .sequence_number(security_version)
        .security_version(security_version)
        .payload_digest(&plaintext_digest, cbor.len() as u64)
        .payload_uri("#hsm-keys".to_string())
        .encryption_info(&encrypted.encryption_info)
        .integrated_payload("#hsm-keys".to_string(), encrypted.ciphertext)
        .text_version(format!("{security_version}.0.0"))
        .text_vendor_name("sumo-provision")
        .text_model_name("HSM-Keys")
        .text_description("HSM trust-anchor keystore")
        .build(&factory_key)
        .map_err(|e| anyhow!("build/sign keystore envelope: {e}"))
}

/// The well-known factory bootstrap key (P-256 scalar=1, public = generator G).
/// Verifies only the first keystore install; replaced by the key-authority
/// anchor afterwards. Built from compile-time constants.
fn factory_signing_key() -> anyhow::Result<CoseKey> {
    let key = coset::CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        FACTORY_SIGNING_PUBLIC[1..33].to_vec(),
        FACTORY_SIGNING_PUBLIC[33..65].to_vec(),
        FACTORY_SIGNING_SCALAR.to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build();
    let bytes = key
        .to_vec()
        .map_err(|e| anyhow!("serialize factory key: {e}"))?;
    CoseKey::from_cose_key_bytes(&bytes).map_err(|e| anyhow!("re-import factory key: {e}"))
}

/// Extract the uncompressed SEC1 point (`0x04 || x || y`) from a COSE_Key CBOR.
pub fn cose_to_sec1(cose_key_cbor: &[u8]) -> anyhow::Result<[u8; 65]> {
    let key = CoseKey::from_cose_key_bytes(cose_key_cbor)
        .map_err(|e| anyhow!("invalid COSE_Key CBOR: {e}"))?;
    let (x, y) = key
        .ec2_public_xy()
        .map_err(|e| anyhow!("not an EC2 P-256 public key: {e}"))?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..65].copy_from_slice(&y);
    Ok(sec1)
}

/// Build a COSE_Key CBOR (EC2 P-256, alg unset) from a SEC1 point — the storable
/// form of the device decrypt pubkey that Tower 2's `build_envelope` and
/// `mint_keystore` both consume.
pub fn sec1_to_cose(sec1: &[u8; 65]) -> Vec<u8> {
    let key = coset::CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        sec1[1..33].to_vec(),
        sec1[33..65].to_vec(),
    )
    .build();
    key.to_vec().expect("serialize device COSE_Key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_produces_a_nonempty_envelope_and_cose_roundtrips() {
        let dev = keygen::generate_device_key(keygen::ES256).unwrap();
        let dev_cose = dev.public_key_bytes();
        let sw = keygen::generate_device_key(keygen::ES256).unwrap();
        let sw_cose = sw.public_key_bytes();
        let ka_sec1 = cose_to_sec1(&dev_cose).unwrap();

        let suit = mint_keystore(&dev_cose, &sw_cose, &ka_sec1, 1, None, &[0x30, 0x82, 0x01, 0x00])
            .unwrap();
        assert!(!suit.is_empty(), "minted keystore SUIT must be non-empty");

        // SEC1 <-> COSE roundtrip (the enrol pubkey conversion path).
        let sec1 = cose_to_sec1(&dev_cose).unwrap();
        let cose = sec1_to_cose(&sec1);
        assert_eq!(cose_to_sec1(&cose).unwrap(), sec1);
    }

    #[test]
    fn assemble_keystore_embeds_tls_leaf_when_provided() {
        let sw = [0x04u8; 65];
        let ka = [0x04u8; 65];
        let leaf = vec![0x30, 0x82, 0x01, 0x00, 0xAB];

        let root = vec![0x30, 0x82, 0x02, 0x00, 0xCA, 0xFE]; // stand-in delegation root DER
        let ks = assemble_keystore(&sw, &ka, 1, Some(&leaf), &root);
        let tls = ks
            .certificates
            .iter()
            .find(|c| c.key_id == KeyRole::TlsIdentity.key_id())
            .expect("tls-identity leaf attached");
        assert_eq!(tls.certificate, leaf);
        // The slot it certifies exists (else payload::decode would reject it).
        assert!(ks
            .slots
            .iter()
            .any(|s| s.key_id == KeyRole::TlsIdentity.key_id()));

        // The delegation root is embedded as a pinned trust anchor.
        let anchor = ks
            .trust_anchors
            .iter()
            .find(|a| a.anchor_id == DELEGATION_ROOT_ANCHOR_ID)
            .expect("delegation root embedded");
        assert_eq!(anchor.certificate, root);

        // No leaf → empty certificates, but the delegation root is always pinned.
        let ks2 = assemble_keystore(&sw, &ka, 1, None, &root);
        assert!(ks2.certificates.is_empty());
        assert_eq!(ks2.trust_anchors.len(), 1);
    }

    #[test]
    fn keystore_emits_no_private_or_symmetric_material() {
        // The Tower keystore is PUBLIC-ONLY. Every device-generated slot — the
        // in-HSM keypairs AND the AES storage key — must ship with NO key
        // material; the HSM generates those locally. Only verify-anchors carry
        // bytes, and those are PUBLIC keys (65-byte uncompressed SEC1).
        let sw = [0x04u8; 65];
        let ka = [0x04u8; 65];
        let root = vec![0x30, 0x82, 0x02, 0x00, 0xCA, 0xFE];
        let ks = assemble_keystore(&sw, &ka, 1, None, &root);

        for &role in KeyRole::mandatory_roles() {
            let slot = ks
                .slots
                .iter()
                .find(|s| s.key_id == role.key_id())
                .expect("every mandatory role has a slot");
            if role.is_device_generated() {
                assert!(
                    slot.anchor_public_key.is_none(),
                    "device-generated slot {} must ship NO key material",
                    role.key_id()
                );
            } else {
                let pk = slot
                    .anchor_public_key
                    .as_ref()
                    .expect("anchor slot carries its public key");
                assert_eq!(pk.len(), 65, "anchor {} public is SEC1", role.key_id());
                assert_eq!(pk[0], 0x04);
            }
        }

        // The lone AES slot: symmetric, device-generated, encrypt/decrypt — and
        // critically carries no key bytes.
        let storage = ks
            .slots
            .iter()
            .find(|s| s.key_id == KeyRole::Storage.key_id())
            .expect("storage-key slot present");
        assert_eq!(storage.key_kind, KEY_TYPE_AES_256);
        assert!(
            storage.anchor_public_key.is_none(),
            "storage-key must ship no key bytes"
        );
        assert_eq!(storage.allowed_ops, Some(vec![OP_ENCRYPT, OP_DECRYPT]));

        // The device's own decoder accepts it — proving the AES "no material"
        // guard (`KeySlot::validate`) is satisfied, not tripped.
        let bytes = payload::encode(&ks).expect("encode");
        payload::decode(&bytes).expect("device decode accepts the public-only keystore");
    }
}
