//! Encrypt-once content encryption for published artifacts.
//!
//! Each artifact is encrypted exactly once under a fresh random AES-256-GCM key
//! (the CEK) and a fresh random nonce. Because the key is single-use, the
//! (key, nonce) pair is unique, so a random nonce is safe. The CEK and nonce are
//! recorded in Tower 2's index; the ciphertext is content-addressed in the blob
//! store.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

/// Size of an AES-256-GCM key, in bytes.
pub const CEK_LEN: usize = 32;
/// Size of the GCM nonce, in bytes.
pub const NONCE_LEN: usize = 12;

/// One artifact's encryption: the fresh key + nonce and the ciphertext.
pub struct Encrypted {
    pub cek: [u8; CEK_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` once under a fresh random key and nonce.
pub fn encrypt_once(plaintext: &[u8]) -> Result<Encrypted, aes_gcm::Error> {
    let mut rng = OsRng;
    let mut cek = [0u8; CEK_LEN];
    rng.fill_bytes(&mut cek);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&cek));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)?;

    Ok(Encrypted {
        cek,
        nonce,
        ciphertext,
    })
}

/// Decrypt a ciphertext produced by [`encrypt_once`]. Test-only today — in
/// production the rig decrypts with the CEK delivered in its per-node manifest;
/// Tower 2 itself never decrypts.
#[cfg(test)]
pub fn decrypt(
    cek: &[u8; CEK_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pt = b"sumo-provision step 1 content core";
        let enc = encrypt_once(pt).unwrap();
        assert_ne!(enc.ciphertext.as_slice(), pt.as_slice());
        let dec = decrypt(&enc.cek, &enc.nonce, &enc.ciphertext).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn wrong_key_fails() {
        let enc = encrypt_once(b"secret").unwrap();
        let mut bad = enc.cek;
        bad[0] ^= 0xff;
        assert!(decrypt(&bad, &enc.nonce, &enc.ciphertext).is_err());
    }
}
