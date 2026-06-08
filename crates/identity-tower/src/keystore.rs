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
    self, HsmKeystore, KeySlot, FACTORY_SIGNING_PUBLIC, FACTORY_SIGNING_SCALAR, KEY_TYPE_EC_P256,
    OP_GET_PUBKEY, OP_SIGN, OP_VERIFY,
};
use hsm::KeyRole;
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
    let ka_sec1 = s.ca.public_sec1().map_err(AppError::Internal)?;

    let suit = mint_keystore(
        &device_decrypt_cose,
        &sw_authority_cose,
        &ka_sec1,
        req.security_version,
    )
    .map_err(AppError::Internal)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        suit,
    ))
}

/// Mint the factory HSM trust-anchor keystore as a signed + encrypted SUIT
/// envelope (component `["hsm","keys"]`, integrated `#hsm-keys` payload).
///
/// - `device_decrypt_cose`    — device decrypt pubkey, COSE_Key CBOR (ECDH recipient).
/// - `sw_authority_cose`      — Tower 2 signer pubkey, COSE_Key CBOR (sw-authority anchor).
/// - `key_authority_pub_sec1` — this CA's pubkey, SEC1 (key-authority anchor).
/// - `security_version`       — anti-rollback floor / SUIT sequence number.
pub fn mint_keystore(
    device_decrypt_cose: &[u8],
    sw_authority_cose: &[u8],
    key_authority_pub_sec1: &[u8; 65],
    security_version: u64,
) -> anyhow::Result<Vec<u8>> {
    let sw_authority_sec1 = cose_to_sec1(sw_authority_cose)?;

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
                // key-authority + platform/application all default to this CA's
                // key for the dev flow; only firmware (sw-authority) is load-
                // bearing here. Add distinct anchors when those tiers go live.
                _ => key_authority_pub_sec1.to_vec(),
            })
        };
        let allowed_ops = if anchor_public_key.is_some() {
            Some(vec![OP_VERIFY, OP_GET_PUBKEY])
        } else {
            Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY])
        };
        slots.push(KeySlot {
            key_id: role.key_id().to_string(),
            key_kind: KEY_TYPE_EC_P256,
            anchor_public_key,
            allowed_guests: None,
            allowed_ops,
        });
    }

    let keystore = HsmKeystore {
        schema_version: payload::SCHEMA_VERSION,
        security_version,
        identities: Vec::new(),
        slots,
    };
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

        let suit = mint_keystore(&dev_cose, &sw_cose, &ka_sec1, 1).unwrap();
        assert!(!suit.is_empty(), "minted keystore SUIT must be non-empty");

        // SEC1 <-> COSE roundtrip (the enrol pubkey conversion path).
        let sec1 = cose_to_sec1(&dev_cose).unwrap();
        let cose = sec1_to_cose(&sec1);
        assert_eq!(cose_to_sec1(&cose).unwrap(), sec1);
    }
}
