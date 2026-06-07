//! Encrypt-once content encryption for published artifacts.
//!
//! Each artifact is encrypted exactly once under a fresh random key (the CEK)
//! and IV via `sumo-offboard` (AES-128-GCM, the same primitive the device-side
//! SUIT envelope uses) — so the stored ciphertext is reusable as a SUIT payload
//! and the CEK can be re-wrapped per device (`rewrap_cek_ecdh`) at flash time
//! without re-encrypting. The CEK + IV are recorded in Tower 2's index; the
//! ciphertext is content-addressed in the blob store; Tower 2 never decrypts.

use sumo_offboard::{encryptor, OffboardError};

/// Size of the AES-128-GCM content-encryption key, in bytes.
pub const CEK_LEN: usize = 16;
/// Size of the GCM IV, in bytes.
pub const NONCE_LEN: usize = 12;

/// One artifact's encryption: the fresh key + IV and the ciphertext.
pub struct Encrypted {
    pub cek: [u8; CEK_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` once under a fresh random CEK + IV. No recipients are
/// wrapped here — the CEK is re-wrapped to each device's key at envelope time.
pub fn encrypt_once(plaintext: &[u8]) -> Result<Encrypted, OffboardError> {
    let enc = encryptor::encrypt_firmware(plaintext, &[])?;
    let iv = encryptor::extract_iv_from_enc_info(&enc.encryption_info)?;
    Ok(Encrypted {
        cek: enc.cek,
        nonce: iv,
        ciphertext: enc.ciphertext,
    })
}

/// Decrypt a ciphertext produced by [`encrypt_once`]. Test-only — in production
/// the rig decrypts with the CEK delivered (re-wrapped) in its SUIT envelope;
/// Tower 2 itself never decrypts.
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

    #[test]
    fn roundtrip() {
        let pt = b"sumo-provision content core, encrypt-once via sumo-offboard";
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
