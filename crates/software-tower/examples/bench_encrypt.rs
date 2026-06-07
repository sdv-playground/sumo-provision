//! Throughput sanity check for sumo-hub's streaming encrypt-once primitive,
//! built under the dev profile so it exercises the same opt-level-3 crypto deps
//! the debug `sumo-hub` binary uses. Mirrors the per-chunk work of a real
//! publish: hash the plaintext (inner), encrypt, hash the ciphertext (outer).
//!
//! Run: `cargo run --example bench_encrypt [MiB]`  (default 512 MiB).

use std::time::Instant;

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use wire::ContentHash;

fn main() {
    let mib: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    let backend = RustCryptoBackend::new();
    let key = [0x42u8; 16];
    let iv = [0x01u8; 12];
    let chunk = vec![0xABu8; 1024 * 1024]; // 1 MiB, reused each iteration

    let mut inner = ContentHash::hasher();
    let mut outer = ContentHash::hasher();
    let mut enc = backend.aes_gcm_encrypt_stream(&key, &iv, &[]).unwrap();
    let mut ct = vec![0u8; chunk.len()];

    let start = Instant::now();
    for _ in 0..mib {
        inner.update(&chunk);
        enc.update(&chunk, &mut ct).unwrap();
        outer.update(&ct);
    }
    let tag = enc.finalize().unwrap();
    outer.update(&tag);
    let _ = (inner.finalize(), outer.finalize());
    let secs = start.elapsed().as_secs_f64();

    println!(
        "hash+encrypt+hash {mib} MiB in {secs:.3}s = {:.0} MiB/s",
        mib as f64 / secs
    );
}
