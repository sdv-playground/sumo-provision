//! Encrypt-once content encryption for published artifacts.
//!
//! Each artifact is encrypted exactly once under a fresh random key (the CEK)
//! and IV, streaming, via `sumo-crypto`'s AES-128-GCM encryptor — the same
//! primitive the device-side SUIT envelope decrypts. The stored ciphertext is
//! therefore reusable as a SUIT payload, and the CEK can be re-wrapped per
//! device (`rewrap_cek_ecdh`) at flash time without re-encrypting. Streaming
//! means a bank image (hundreds of MB) never has to sit in memory in full: the
//! upload handler feeds the request body through this encryptor chunk by chunk.
//! The CEK + IV are recorded in Tower 2's index; the ciphertext is
//! content-addressed in the blob store; Tower 2 itself never decrypts.

use sumo_crypto::streaming::StreamingAeadEncryptor;
use sumo_crypto::{CryptoBackend, CryptoError, RustCryptoBackend};

/// Size of the AES-128-GCM content-encryption key, in bytes.
pub const CEK_LEN: usize = 16;
/// Size of the GCM IV, in bytes.
pub const NONCE_LEN: usize = 12;

/// A streaming AES-128-GCM encryption under a fresh random CEK + IV — the
/// encrypt-once primitive. Feed plaintext chunks with [`update`](Self::update),
/// then [`finish`](Self::finish) for the trailing GCM tag. The complete
/// ciphertext is the concatenation of every `update` output followed by the
/// `finish` tag. `cek` / `nonce` are exposed so the caller can record them in
/// the index; no recipients are wrapped here (the CEK is re-wrapped to each
/// device's key at envelope time).
pub struct StreamEncryptor {
    pub cek: [u8; CEK_LEN],
    pub nonce: [u8; NONCE_LEN],
    inner: Box<dyn StreamingAeadEncryptor>,
}

impl StreamEncryptor {
    /// Begin an encryption under a freshly generated random CEK + IV.
    pub fn new() -> Result<Self, CryptoError> {
        let backend = RustCryptoBackend::new();
        let mut cek = [0u8; CEK_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        backend.random_bytes(&mut cek)?;
        backend.random_bytes(&mut nonce)?;
        let inner = backend.aes_gcm_encrypt_stream(&cek, &nonce, &[])?;
        Ok(Self { cek, nonce, inner })
    }

    /// Encrypt one chunk of plaintext, writing its ciphertext into `out` (the
    /// buffer is reused across chunks to avoid per-chunk allocation).
    pub fn update(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        out.clear();
        out.resize(plaintext.len(), 0);
        self.inner.update(plaintext, out)?;
        Ok(())
    }

    /// Finish the encryption, returning the 16-byte GCM tag to append.
    pub fn finish(&mut self) -> Result<[u8; 16], CryptoError> {
        self.inner.finalize()
    }
}

/// Decrypt a ciphertext produced by [`StreamEncryptor`]. Test-only — in
/// production the rig decrypts with the CEK delivered (re-wrapped) in its SUIT
/// envelope; Tower 2 itself never decrypts.
#[cfg(test)]
pub fn decrypt(
    cek: &[u8; CEK_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes128Gcm, Key, Nonce};
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(cek));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt `pt` through the streaming encryptor in small chunks, returning
    /// the complete ciphertext (chunks + tag) plus the CEK and IV.
    fn encrypt_streaming(pt: &[u8]) -> (Vec<u8>, [u8; CEK_LEN], [u8; NONCE_LEN]) {
        let mut enc = StreamEncryptor::new().unwrap();
        let (cek, nonce) = (enc.cek, enc.nonce);
        let mut ciphertext = Vec::new();
        let mut buf = Vec::new();
        for chunk in pt.chunks(7) {
            enc.update(chunk, &mut buf).unwrap();
            ciphertext.extend_from_slice(&buf);
        }
        ciphertext.extend_from_slice(&enc.finish().unwrap());
        (ciphertext, cek, nonce)
    }

    #[test]
    fn roundtrip() {
        let pt = b"sumo-provision content core, encrypt-once streaming via sumo-crypto";
        let (ciphertext, cek, nonce) = encrypt_streaming(pt);
        assert_ne!(ciphertext.as_slice(), pt.as_slice());
        let dec = decrypt(&cek, &nonce, &ciphertext).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn wrong_key_fails() {
        let (ciphertext, cek, nonce) = encrypt_streaming(b"secret");
        let mut bad = cek;
        bad[0] ^= 0xff;
        assert!(decrypt(&bad, &nonce, &ciphertext).is_err());
    }
}
