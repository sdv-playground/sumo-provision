//! The **delegated-rights X.509 extension** — Tower 1's (the CA's) copy.
//!
//! In the delegation trust model (`docs/design/authorization.md` §5/§6) a device
//! pins only *roots* (online/Tower + onboard). A delegate — e.g. the workshop
//! minter — is **not** pinned; it presents a cert chained to a pinned root, and the
//! capabilities it is permitted to grant ride in **its own cert** as this extension,
//! signed by the issuing root. Because the root vouches for exactly these scopes, a
//! delegate **cannot self-escalate**: the verifier honours a token's capability only
//! if the signing delegate's cert grants it.
//!
//! Wire form: a non-critical X.509 v3 extension whose value is a DER `UTF8String` of
//! space-delimited capability scopes (same grammar as the JWT `scope` claim), e.g.
//! `"reset:execute update:transfer update:verdict"`.
//!
//! # Lockstep with the verifier
//!
//! This is a **deliberate duplicate** of the verifier's copy in
//! `sumo-machine-manager/crates/vm-mgr/src/sovd/delegated_rights.rs`. We mint here;
//! vm-mgr reads. The two MUST stay byte-for-byte identical: same
//! [`DELEGATED_RIGHTS_OID`] **and** the same wire form (a bare `UTF8String`). We do
//! NOT depend on vm-mgr — it's the heavy OTA engine in another submodule, the wrong
//! layer for an identity CA to pull in — so the extension is small enough to carry
//! its own copy. Change one side, change the other.

use const_oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::asn1::Utf8StringRef;
use x509_cert::der::{self, Encode};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;

/// OID for the delegated-rights extension. MUST equal vm-mgr's copy.
///
/// **PLACEHOLDER** under a private arc — assign the real TRATON/CSI enterprise arc
/// (`1.3.6.1.4.1.<PEN>…`) before this leaves dev. (Mirror the change in vm-mgr.)
pub const DELEGATED_RIGHTS_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1");

/// Issuance newtype for the delegated-rights extension, for use with
/// [`x509_cert::builder::CertificateBuilder::add_extension`].
///
/// Holds the space-delimited scope string. Its DER form is a **bare
/// `UTF8String`** (no `SEQUENCE`, no `OCTET STRING` wrapper) — the builder's
/// `AsExtension::to_extension` is what wraps that in the extension's
/// `extn_value` `OCTET STRING`. That makes the on-the-wire bytes identical to the
/// verifier's, so vm-mgr's `granted_scopes` reads it back unchanged.
pub struct DelegatedRightsExt(pub String);

impl AssociatedOid for DelegatedRightsExt {
    const OID: ObjectIdentifier = DELEGATED_RIGHTS_OID;
}

impl Encode for DelegatedRightsExt {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Utf8StringRef::new(&self.0)?.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Utf8StringRef::new(&self.0)?.encode(encoder)
    }
}

impl AsExtension for DelegatedRightsExt {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        // Non-critical: a verifier predating the extension grants nothing extra
        // rather than rejecting the cert (see module docs).
        false
    }
}
