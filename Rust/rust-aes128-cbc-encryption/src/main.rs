// aes128_cbc_demo.rs — AES-128-CBC encryption with PKCS#7 padding.
//
// This is the "before" picture for a Rust service using legacy
// symmetric encryption. AES-128-CBC was widely deployed pre-2020
// in disk-at-rest, TLS 1.0/1.1, and many file-encryption tools.
// It has multiple problems even before considering the quantum
// question:
//
// What PostQ would flag:
//   - Algorithm:          AES-CBC
//   - Key size:           128 bits  (sub-quantum-safe; AES-256 is
//                                    the recommended floor for
//                                    long-lived data)
//   - Mode:               CBC  (vulnerable to padding-oracle
//                               attacks if not carefully wrapped;
//                               GCM is the modern AEAD mode)
//   - Quantum exposure:   Reduced (Grover's algorithm halves
//                                  effective key size: AES-128
//                                  effective security against
//                                  quantum is ~64 bits — too low)
//   - Migration target:   AES-256-GCM (FIPS-approved AEAD, raises
//                                      effective post-quantum
//                                      security to ~128 bits)
//
// Note: AES is symmetric, so unlike RSA/ECDSA it is not BROKEN by
// quantum — just WEAKENED. The recommended response is to upgrade
// the key size, not switch algorithm families.
//
// Run:  cargo run --release
//       (downloads aes, cbc, rand, hex crates)

use aes::Aes128;
use cbc::{Encryptor, Decryptor, cipher::{block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut, KeyIvInit}};
use rand::RngCore;

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

const KEY_SIZE_BYTES: usize = 16;   // AES-128 (sub-quantum-safe)
const IV_SIZE_BYTES: usize = 16;

fn main() {
    println!("=== PostQ Demo Library: AES-128-CBC Encryption in Rust (classical, weak) ===");
    println!();

    // 1. Generate a fresh AES-128 key + IV.
    let mut key = [0u8; KEY_SIZE_BYTES];
    let mut iv = [0u8; IV_SIZE_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut iv);

    println!("[1/4] Generated AES-128 key + CBC IV");
    println!("      Algorithm:        AES-CBC");
    println!("      Key size:         {} bits", KEY_SIZE_BYTES * 8);
    println!("      Mode:             CBC with PKCS#7 padding");
    println!("      Key (hex):        {}", hex::encode(key));
    println!("      IV (hex):         {}", hex::encode(iv));
    println!();

    // 2. Encrypt a message.
    let message = b"Settle TX-2026-04823 for confidential payment of \xC2\xA31,250,000";
    let mut buffer = vec![0u8; message.len() + KEY_SIZE_BYTES];
    buffer[..message.len()].copy_from_slice(message);

    let cipher = Aes128CbcEnc::new(&key.into(), &iv.into());
    let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, message.len())
        .expect("encryption failed");

    println!("[2/4] Encrypted message");
    println!("      Plaintext len:  {} bytes", message.len());
    println!("      Ciphertext len: {} bytes", ciphertext.len());
    println!("      Ciphertext (hex, first 64 chars):");
    println!("        {}...", hex::encode(&ciphertext[..32]));
    println!();

    // 3. Decrypt.
    let mut decrypt_buffer = ciphertext.to_vec();
    let cipher = Aes128CbcDec::new(&key.into(), &iv.into());
    let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut decrypt_buffer)
        .expect("decryption failed");

    println!("[3/4] Decrypted ciphertext");
    println!("      Recovered:    {}", String::from_utf8_lossy(plaintext));
    println!("      Match:        {}", plaintext == message);
    println!();

    // 4. Tampered ciphertext (note: CBC has no built-in integrity check, so
    //    tampering may produce garbage plaintext but won't be REJECTED.
    //    This is one of CBC's biggest weaknesses — use AES-GCM for AEAD.)
    let mut tampered = ciphertext.to_vec();
    tampered[8] ^= 0xFF;  // flip a byte
    let cipher = Aes128CbcDec::new(&key.into(), &iv.into());
    let mut tamper_buf = tampered.clone();
    let tamper_result = cipher.decrypt_padded_mut::<Pkcs7>(&mut tamper_buf);

    println!("[4/4] Tampered ciphertext decryption");
    match tamper_result {
        Ok(pt) => {
            println!("      Result:       DECRYPTED — but plaintext is corrupted!");
            println!("      Output (lossy):  {:?}", String::from_utf8_lossy(pt));
            println!("      ↑ This is exactly CBC's weakness: no integrity check.");
            println!("        AES-GCM would have rejected this with an auth error.");
        }
        Err(e) => {
            println!("      Result:       REJECTED (padding error: {:?})", e);
            println!("      ↑ Padding-oracle leakage — CBC's other weakness.");
        }
    }
    println!();

    // PostQ migration verdict.
    println!("=== PostQ Migration Verdict ===");
    println!();
    println!("  Algorithm:           AES-128-CBC");
    println!("  Quantum exposure:    Reduced (Grover halves to ~64 bits)");
    println!("  Classical exposure:  Medium (CBC has padding-oracle history;");
    println!("                              AES-128 is sub-quantum-safe floor)");
    println!("  Migration target:    AES-256-GCM (FIPS-approved AEAD)");
    println!("  Hybrid intermediate: N/A — symmetric, no hybrid mode needed");
    println!();
    println!("  Compare with:        rust-aes256-gcm-encryption/aes256_gcm_demo.rs");
    println!();
}
