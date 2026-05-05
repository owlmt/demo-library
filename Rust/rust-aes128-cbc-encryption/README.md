# rust-aes128-cbc-encryption — AES-128-CBC in Rust

A self-contained Rust binary that encrypts a message with AES-128
in CBC mode using PKCS#7 padding, decrypts it, and demonstrates
that CBC has no built-in integrity protection.

The **"before"** picture for a Rust service using legacy symmetric
encryption. This exact pattern appears in disk-encryption tools,
file-encryption utilities, TLS 1.0/1.1 implementations, and many
Rust web services pre-2020.

## Three findings, not one

PostQ flags **three distinct issues** on this code:

1. **Key size too small.** AES-128 has only ~64 bits of effective
   post-quantum security after Grover's algorithm. AES-256 is the
   recommended floor for any data with multi-year retention.
2. **CBC mode without integrity.** CBC is vulnerable to
   padding-oracle attacks and provides no authentication. AEAD modes
   (AES-GCM, AES-OCB, ChaCha20-Poly1305) are the modern standard.
3. **PKCS#7 padding.** Required for CBC but introduces the padding
   oracle attack surface.

This makes Rust the strongest signal in the demo set for the
"weakness compounds" story.

## Running

```bash
./run.sh
```

Or:

```bash
cargo run --release
```

Requires Rust 1.70+. First run downloads `aes`, `cbc`, `rand`, and
`hex` crates (~30 seconds).

## What PostQ would flag

| Field | Value |
|---|---|
| Language | Rust |
| Algorithm | AES |
| Key size | 128 bits (sub-quantum-safe floor) |
| Mode | CBC (no AEAD; no integrity) |
| Padding | PKCS#7 (padding-oracle surface) |
| Quantum exposure | Reduced (Grover halves effective security) |
| Classical exposure | Medium (legacy mode, known weaknesses) |
| Migration target | AES-256-GCM |

## On symmetric vs asymmetric quantum risk

Unlike RSA/ECDSA (which Shor's algorithm BREAKS), AES is symmetric
and only WEAKENED by quantum computing. Grover's algorithm halves
the effective key size:

- AES-128 → ~64-bit effective security (too low)
- AES-192 → ~96-bit effective security (acceptable)
- AES-256 → ~128-bit effective security (recommended)

The migration is an upgrade, not a replacement of algorithm family.

## After migration

Matching post-migration example will land at:

```
demo-library/rust-aes256-gcm-encryption/aes256_gcm_demo.rs
```

## License

MIT. Educational sample only.
