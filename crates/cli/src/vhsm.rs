//! Off-box vHSM enrollment provisioning (protocol.md §11).
//!
//! Two operator paths for giving a guest its vHSM identity:
//!
//! - **Bootstrap token** ([`generate_token`] / [`token_sha256_hex`] /
//!   [`bootstrap_yaml_fragment`]): a single-use credential the guest
//!   exchanges for a long-lived CWT cert via the daemon's in-box ENROLL
//!   handshake. The raw 32 bytes go into the guest's firmware bank at
//!   `<bank>/vhsm-bootstrap.token`; the daemon-side state records only
//!   the SHA-256. This is the common first-boot path.
//!
//! - **Off-box CWT mint** ([`mint_cwt`]): mint the cert directly with a
//!   local `ecu-signing` key — pre-provisioning ahead of deployment,
//!   cert rotation without re-ENROLL, test fixtures. Same on-wire
//!   layout as the daemon's in-box minter; the claim labels and
//!   audience come from `vhsm_proto::cwt`, the shared contract both
//!   ends import.
//!
//! Ported from the public SUIT library (sumo-offboard `cwt`/`bootstrap`,
//! retired there): product-specific provisioning belongs beside the
//! towers, not in the vendor-neutral manifest library.

use anyhow::{bail, Context as _};
use ciborium::value::{Integer, Value as CborValue};
use coset::iana::{Algorithm as CoseAlg, EllipticCurve as CoseEc};
use coset::{AsCborValue, CborSerializable, CoseKey, CoseSign1Builder, HeaderBuilder};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use vhsm_proto::cwt::{
    CLAIM_AUD, CLAIM_CNF, CLAIM_CTI, CLAIM_EXP, CLAIM_IAT, CLAIM_ISS, CLAIM_NBF, CLAIM_SUB,
    COSE_KEY_EC2_CRV, COSE_KEY_EC2_X, COSE_KEY_EC2_Y, VHSM_AUDIENCE,
};

// ---- CWT mint ---------------------------------------------------------------

/// CWT validity window, in Unix seconds.
#[derive(Debug, Clone, Copy)]
pub struct ValidityWindow {
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
}

impl ValidityWindow {
    /// Convenience: `iat = now`, `nbf = now`, `exp = now + lifetime_secs`.
    pub fn from_now(now_unix: u64, lifetime_secs: u64) -> Self {
        Self {
            iat: now_unix,
            nbf: now_unix,
            exp: now_unix.saturating_add(lifetime_secs),
        }
    }
}

/// Mint a CWT signed by `signing_key`.
///
/// `cnf_pub_x` and `cnf_pub_y` are the 32-byte coordinates of the
/// guest's identity pubkey (P-256). Caller is responsible for
/// splitting the SEC1 `0x04 || x || y` representation if that's the
/// source format.
pub fn mint_cwt(
    signing_key: &SigningKey,
    subject: &str,
    issuer: &str,
    cnf_pub_x: &[u8],
    cnf_pub_y: &[u8],
    validity: ValidityWindow,
) -> anyhow::Result<Vec<u8>> {
    if cnf_pub_x.len() != 32 || cnf_pub_y.len() != 32 {
        bail!(
            "cnf pubkey coordinates must be 32 bytes each (x={}, y={})",
            cnf_pub_x.len(),
            cnf_pub_y.len()
        );
    }

    let cnf_cose_key = CoseKey {
        kty: coset::RegisteredLabel::Assigned(coset::iana::KeyType::EC2),
        alg: Some(coset::RegisteredLabelWithPrivate::Assigned(CoseAlg::ES256)),
        params: vec![
            (
                coset::Label::Int(COSE_KEY_EC2_CRV),
                CborValue::Integer(Integer::from(CoseEc::P_256 as i64)),
            ),
            (
                coset::Label::Int(COSE_KEY_EC2_X),
                CborValue::Bytes(cnf_pub_x.to_vec()),
            ),
            (
                coset::Label::Int(COSE_KEY_EC2_Y),
                CborValue::Bytes(cnf_pub_y.to_vec()),
            ),
        ],
        ..Default::default()
    };

    let cnf_val = cnf_cose_key
        .to_cbor_value()
        .map_err(|e| anyhow::anyhow!("encode cnf COSE_Key: {e}"))?;
    let cnf_wrapped = CborValue::Map(vec![(CborValue::Integer(Integer::from(1i64)), cnf_val)]);

    let mut cti = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cti);

    let claims = CborValue::Map(vec![
        (
            CborValue::Integer(Integer::from(CLAIM_ISS)),
            CborValue::Text(issuer.to_string()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_SUB)),
            CborValue::Text(subject.to_string()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_AUD)),
            CborValue::Text(VHSM_AUDIENCE.to_string()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_EXP)),
            CborValue::Integer(Integer::from(validity.exp)),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_NBF)),
            CborValue::Integer(Integer::from(validity.nbf)),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_IAT)),
            CborValue::Integer(Integer::from(validity.iat)),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_CTI)),
            CborValue::Bytes(cti.to_vec()),
        ),
        (CborValue::Integer(Integer::from(CLAIM_CNF)), cnf_wrapped),
    ]);

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&claims, &mut payload_bytes).context("encode CWT payload")?;

    let cose = CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(CoseAlg::ES256).build())
        .payload(payload_bytes)
        .create_signature(b"", |data| {
            let sig: Signature = signing_key.sign(data);
            sig.to_vec()
        })
        .build();
    cose.to_vec()
        .map_err(|e| anyhow::anyhow!("encode COSE_Sign1: {e}"))
}

// ---- Bootstrap tokens -------------------------------------------------------

/// Length of a bootstrap token in bytes. Sized to match the daemon
/// side's expected raw-token range (1..=255; we ship 32).
pub const TOKEN_LEN: usize = 32;

/// Generate a fresh bootstrap token via the OS CSPRNG. 32 random
/// bytes. Output is uniformly random; do not log it or copy it
/// through the network.
pub fn generate_token() -> [u8; TOKEN_LEN] {
    let mut t = [0u8; TOKEN_LEN];
    rand::thread_rng().fill_bytes(&mut t);
    t
}

/// Lower-hex SHA-256 of a raw bootstrap token (64 chars).
///
/// This is the exact format the daemon writes into its
/// `bootstrap.yaml`. Use [`bootstrap_yaml_fragment`] to format a
/// complete YAML entry.
pub fn token_sha256_hex(raw_token: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(raw_token);
    hex::encode(h.finalize())
}

/// Build a YAML fragment for a single fresh (un-consumed) bootstrap
/// entry. Indentation is 2-space, vm_id is quoted to defend against
/// names that happen to look like YAML keywords.
///
/// Operators merge this into the `tokens:` map of an existing
/// `bootstrap.yaml`. The daemon's `BootstrapState::load` reads any
/// file with the same shape produced by its own `save()`.
pub fn bootstrap_yaml_fragment(vm_id: &str, sha256_hex: &str) -> String {
    format!(
        "  \"{}\":\n    sha256: \"{}\"\n    consumed: false\n",
        yaml_escape(vm_id),
        sha256_hex,
    )
}

/// Build a full standalone `bootstrap.yaml` document carrying a
/// single fresh entry. Useful for first-time provisioning where the
/// file doesn't exist yet.
pub fn bootstrap_yaml_document(vm_id: &str, sha256_hex: &str) -> String {
    format!("tokens:\n{}", bootstrap_yaml_fragment(vm_id, sha256_hex))
}

/// Minimal YAML string escape — handles quote / backslash. Bootstrap
/// vm_ids are short identifiers (matching the daemon's principal
/// vocabulary), so we don't need full YAML escaping.
fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CoseSign1;
    use p256::ecdsa::{signature::Verifier as _, VerifyingKey};
    use p256::EncodedPoint;
    use rand::rngs::OsRng;

    fn sec1_split(sk: &SigningKey) -> (Vec<u8>, Vec<u8>) {
        let vk = sk.verifying_key();
        let p = vk.to_encoded_point(false);
        let bytes = p.as_bytes();
        (bytes[1..33].to_vec(), bytes[33..65].to_vec())
    }

    #[test]
    fn minted_cwt_verifies_under_signer_pub() {
        let signer = SigningKey::random(&mut OsRng);
        let identity = SigningKey::random(&mut OsRng);
        let (x, y) = sec1_split(&identity);
        let cwt = mint_cwt(
            &signer,
            "vm9",
            "device-fleet-7",
            &x,
            &y,
            ValidityWindow::from_now(1_700_000_000, 86_400),
        )
        .unwrap();

        let cose = CoseSign1::from_slice(&cwt).expect("parse COSE_Sign1");
        let pk = signer.verifying_key().to_encoded_point(false);
        let point = EncodedPoint::from_bytes(pk.as_bytes()).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        cose.verify_signature(b"", |sig, data| {
            let sig = Signature::from_slice(sig).map_err(|_| ())?;
            vk.verify(data, &sig).map_err(|_| ())
        })
        .expect("CWT signature should verify under signer's pub");
    }

    #[test]
    fn minted_cwt_audience_matches_daemon_contract() {
        // The whole point of the vhsm-proto::cwt move: mint under the
        // SAME audience constant the daemon validates against.
        let signer = SigningKey::random(&mut OsRng);
        let identity = SigningKey::random(&mut OsRng);
        let (x, y) = sec1_split(&identity);
        let cwt = mint_cwt(
            &signer,
            "vm9",
            "device-fleet-7",
            &x,
            &y,
            ValidityWindow::from_now(1_700_000_000, 86_400),
        )
        .unwrap();

        let cose = CoseSign1::from_slice(&cwt).unwrap();
        let payload = cose.payload.as_deref().unwrap();
        let val: CborValue = ciborium::de::from_reader(payload).unwrap();
        let map = match val {
            CborValue::Map(m) => m,
            _ => panic!("payload not a map"),
        };
        let aud = map.iter().find_map(|(k, v)| match (k, v) {
            (CborValue::Integer(i), CborValue::Text(s)) if i128::from(*i) == CLAIM_AUD as i128 => {
                Some(s.clone())
            }
            _ => None,
        });
        assert_eq!(aud.as_deref(), Some(VHSM_AUDIENCE));
    }

    #[test]
    fn rejects_wrong_length_pubkey_coords() {
        let signer = SigningKey::random(&mut OsRng);
        let err = mint_cwt(
            &signer,
            "vm9",
            "device-test",
            &[0u8; 31],
            &[0u8; 32],
            ValidityWindow::from_now(0, 1),
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("cnf pubkey"));
    }

    #[test]
    fn cti_is_unique_across_two_mints() {
        let signer = SigningKey::random(&mut OsRng);
        let identity = SigningKey::random(&mut OsRng);
        let (x, y) = sec1_split(&identity);
        let v = ValidityWindow::from_now(1_700_000_000, 86_400);
        let a = mint_cwt(&signer, "vm9", "device-test", &x, &y, v).unwrap();
        let b = mint_cwt(&signer, "vm9", "device-test", &x, &y, v).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generated_token_is_correct_length_and_random() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), TOKEN_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_matches_known_vector() {
        let hex = token_sha256_hex(b"");
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn yaml_fragment_round_trips_through_serde_yaml() {
        let frag = bootstrap_yaml_fragment("vm9", "abc123");
        let doc = format!("tokens:\n{frag}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap();
        let entry = &parsed["tokens"]["vm9"];
        assert_eq!(entry["sha256"], "abc123");
        assert_eq!(entry["consumed"], false);
    }

    #[test]
    fn yaml_escapes_quote_and_backslash_in_vm_id() {
        let frag = bootstrap_yaml_fragment("vm\"\\test", "00");
        let doc = format!("tokens:\n{frag}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap();
        let map = parsed["tokens"].as_mapping().unwrap();
        let keys: Vec<&str> = map.keys().filter_map(|k| k.as_str()).collect();
        assert_eq!(keys, vec!["vm\"\\test"]);
    }

    #[test]
    fn yaml_document_is_self_contained() {
        let doc = bootstrap_yaml_document("vm-test", "deadbeef");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap();
        assert_eq!(parsed["tokens"]["vm-test"]["sha256"], "deadbeef");
        assert_eq!(parsed["tokens"]["vm-test"]["consumed"], false);
    }
}
