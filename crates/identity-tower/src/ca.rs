//! The device CA: a self-signed P-256 root that signs a device CSR into a
//! `clientAuth` leaf certificate — the "CSR response", reusable as the device's
//! mTLS client identity. Pure (no DB); the persisted key+cert are generated on
//! first run (mirroring Tower 2's signer, `software-tower/src/main.rs`).

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use const_oid::db::rfc5280::ID_KP_CLIENT_AUTH;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::request::CertReq;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

/// The key-authority root DN — signs HSM key material (keystore envelopes); its
/// public half is the `key-authority` anchor provisioned into each device.
pub const KEY_AUTHORITY_ROOT_DN: &str = "CN=sumo-ca root,O=sumo";
/// The device **identity** root DN — a DISTINCT CA: it signs device TLS leaf
/// certs, and its public half is the fleet-wide identity trust anchor every node
/// pins to verify a peer's leaf. Kept separate from key-authority and
/// sw-authority so the identity trust domain never overlaps the others.
pub const IDENTITY_ROOT_DN: &str = "CN=sumo identity root,O=sumo";
const ROOT_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 3600);
const LEAF_VALIDITY: Duration = Duration::from_secs(825 * 24 * 3600); // CA/B max

/// The device CA — a P-256 signing key plus its self-signed root cert.
pub struct Ca {
    signing_key: SigningKey,
    cert: Certificate,
    issuer: Name,
}

/// A freshly issued device certificate and its metadata.
pub struct IssuedCert {
    pub der: Vec<u8>,
    pub pem: String,
    pub serial_hex: String,
    pub not_after: String,   // RFC3339
    pub fingerprint: String, // sha256:<hex>
    pub pubkey_hex: String,  // 65-byte uncompressed EC point, hex
}

impl Ca {
    /// Generate a fresh P-256 CA: random key + self-signed root.
    pub fn generate(root_dn: &str) -> anyhow::Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let issuer = Name::from_str(root_dn)?;
        let spki = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key())?;
        let builder = CertificateBuilder::new(
            Profile::Root,
            random_serial()?,
            Validity::from_now(ROOT_VALIDITY)?,
            issuer.clone(),
            spki,
            &signing_key,
        )?;
        let cert: Certificate = builder.build::<DerSignature>()?;
        Ok(Self {
            signing_key,
            cert,
            issuer,
        })
    }

    /// Load a CA from a PKCS#8 DER key + DER root cert.
    pub fn load(key_path: &Path, cert_path: &Path) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from_pkcs8_der(&std::fs::read(key_path)?)?;
        let cert = Certificate::from_der(&std::fs::read(cert_path)?)?;
        let issuer = cert.tbs_certificate.subject.clone();
        Ok(Self {
            signing_key,
            cert,
            issuer,
        })
    }

    /// Persist the CA: PKCS#8 DER key (0600) + DER root cert.
    pub fn save(&self, key_path: &Path, cert_path: &Path) -> anyhow::Result<()> {
        if let Some(p) = key_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(key_path, self.signing_key.to_pkcs8_der()?.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::write(cert_path, self.cert.to_der()?)?;
        Ok(())
    }

    /// The CA root certificate, PEM (the trust anchor a verifier pins).
    pub fn root_cert_pem(&self) -> anyhow::Result<String> {
        Ok(self.cert.to_pem(LineEnding::LF)?)
    }

    /// The CA public key as an uncompressed SEC1 point (`0x04 || x || y`) — used
    /// as the `key-authority` trust anchor when minting a device keystore.
    pub fn public_sec1(&self) -> anyhow::Result<[u8; 65]> {
        let spki = SubjectPublicKeyInfoOwned::from_key(*self.signing_key.verifying_key())?;
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("CA public key is not octet-aligned"))?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("CA public key is not a 65-byte P-256 point"))
    }

    /// Parse + POP-verify a PKCS#10 CSR (DER or PEM) and issue a `clientAuth`
    /// leaf bound to `device_id`, signed by this CA.
    pub fn issue_leaf(&self, device_id: &str, csr_bytes: &[u8]) -> anyhow::Result<IssuedCert> {
        let csr = parse_and_verify_csr(csr_bytes)?;
        let pubkey_hex = hex::encode(
            csr.info
                .public_key
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| anyhow::anyhow!("CSR public key is not octet-aligned"))?,
        );

        let subject = Name::from_str(&format!("CN={device_id}"))?;
        let serial = random_serial()?;
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: self.issuer.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial.clone(),
            Validity::from_now(LEAF_VALIDITY)?,
            subject,
            csr.info.public_key.clone(),
            &self.signing_key,
        )?;
        builder.add_extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]))?;
        let cert: Certificate = builder.build::<DerSignature>()?;

        let der = cert.to_der()?;
        let not_after = fmt_rfc3339(cert.tbs_certificate.validity.not_after);
        Ok(IssuedCert {
            pem: cert.to_pem(LineEnding::LF)?,
            serial_hex: hex::encode(serial.as_bytes()),
            not_after,
            fingerprint: wire::ContentHash::of(&der).to_prefixed(),
            pubkey_hex,
            der,
        })
    }
}

/// Parse a PKCS#10 CSR (DER, with PEM fallback) and verify its self-signature
/// (proof the requester holds the private key). P-256 / ECDSA-SHA256 only.
fn parse_and_verify_csr(bytes: &[u8]) -> anyhow::Result<CertReq> {
    let csr = CertReq::from_der(bytes).or_else(|_| CertReq::from_pem(bytes))?;
    let info_der = csr.info.to_der()?;
    let spki_der = csr.info.public_key.to_der()?;
    let vk = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| anyhow::anyhow!("CSR public key is not a P-256 key"))?;
    let sig = DerSignature::try_from(
        csr.signature
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("CSR signature is not octet-aligned"))?,
    )?;
    vk.verify(&info_der, &sig)
        .map_err(|_| anyhow::anyhow!("CSR self-signature (proof-of-possession) failed"))?;
    Ok(csr)
}

/// A random positive 20-byte serial (RFC 5280 §4.1.2.2).
fn random_serial() -> anyhow::Result<SerialNumber> {
    let mut b = [0u8; 20];
    OsRng.fill_bytes(&mut b);
    b[0] &= 0x7f;
    b[0] |= 0x01;
    Ok(SerialNumber::new(&b)?)
}

/// Format an X.509 `Time` as RFC3339 (UTC, no chrono).
fn fmt_rfc3339(t: x509_cert::time::Time) -> String {
    let dt = t.to_date_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::builder::RequestBuilder;

    /// Build a fixture device CSR with a fresh P-256 key (as the rig would).
    fn fixture_csr(cn: &str) -> (SigningKey, Vec<u8>) {
        let device_key = SigningKey::random(&mut OsRng);
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let builder = RequestBuilder::new(subject, &device_key).unwrap();
        let csr = builder.build::<DerSignature>().unwrap();
        (device_key, csr.to_der().unwrap())
    }

    #[test]
    fn issues_clientauth_leaf_that_chains_to_root() {
        let ca = Ca::generate(KEY_AUTHORITY_ROOT_DN).unwrap();
        let (_dk, csr) = fixture_csr("rig-001");
        let issued = ca.issue_leaf("rig-001", &csr).unwrap();

        let leaf = Certificate::from_der(&issued.der).unwrap();
        assert_eq!(leaf.tbs_certificate.issuer, ca.issuer);
        assert!(format!("{}", leaf.tbs_certificate.subject).contains("rig-001"));

        // Chains to the CA: the leaf's TBS verifies under the CA's key.
        let tbs = leaf.tbs_certificate.to_der().unwrap();
        let sig = DerSignature::try_from(leaf.signature.as_bytes().unwrap()).unwrap();
        ca.signing_key.verifying_key().verify(&tbs, &sig).unwrap();

        // clientAuth EKU present.
        let eku = leaf
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .any(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE);
        assert!(eku, "leaf must carry an extendedKeyUsage extension");
    }

    #[test]
    fn rejects_tampered_csr() {
        let ca = Ca::generate(KEY_AUTHORITY_ROOT_DN).unwrap();
        let (_dk, mut csr) = fixture_csr("rig-002");
        let n = csr.len();
        csr[n - 1] ^= 0xff; // corrupt the signature
        assert!(ca.issue_leaf("rig-002", &csr).is_err());
    }

    #[test]
    fn save_load_roundtrip_preserves_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("ca-authority.key");
        let cert = dir.path().join("ca-cert.der");
        let ca = Ca::generate(KEY_AUTHORITY_ROOT_DN).unwrap();
        ca.save(&key, &cert).unwrap();
        let reloaded = Ca::load(&key, &cert).unwrap();
        assert_eq!(reloaded.issuer, ca.issuer);
    }

    #[test]
    fn identity_root_is_distinct_from_key_authority() {
        let key_authority = Ca::generate(KEY_AUTHORITY_ROOT_DN).unwrap();
        let identity = Ca::generate(IDENTITY_ROOT_DN).unwrap();
        // Distinct keys → distinct trust domains.
        assert_ne!(
            key_authority.public_sec1().unwrap(),
            identity.public_sec1().unwrap()
        );

        // A device leaf chains to the IDENTITY root, never the key-authority one.
        let (_dk, csr) = fixture_csr("node-7");
        let issued = identity.issue_leaf("node-7", &csr).unwrap();
        let leaf = Certificate::from_der(&issued.der).unwrap();
        assert_eq!(leaf.tbs_certificate.issuer, identity.issuer);
        assert_ne!(leaf.tbs_certificate.issuer, key_authority.issuer);
        assert!(format!("{}", identity.issuer).contains("identity root"));
    }
}
