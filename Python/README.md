# python-rsa-encryption — RSA-1024 with OAEP padding

A small, self-contained Python program that generates a 1024-bit RSA
keypair, encrypts a message with OAEP/SHA-256 padding, decrypts it,
and demonstrates that a tampered ciphertext fails decryption.

This is the **"before"** picture for a PostQ migration on the
encryption / key-encapsulation side. It runs today, on Python 3.10+,
with one dependency: `cryptography`.

## Why this matters

RSA-1024 is **already broken** for any production use:

- NIST has disallowed RSA-1024 since 2013.
- FIPS 140-3 requires minimum 2048-bit RSA.
- NSA CNSA 2.0 disallows RSA at any key size for national security
  systems by 2035.
- Independent of the quantum question, sustained classical compute
  can already factor 1024-bit RSA in offline analysis. Anything
  encrypted with RSA-1024 today should be considered exposed.

PostQ scans codebases like this one and produces:
- A **CBOM** entry recording the algorithm, key size, padding scheme,
  and call sites.
- A **risk score** computed from quantum exposure, classical
  exposure (RSA-1024 specifically), business criticality, and
  migration complexity.
- A **migration backlog entry** sequenced against your other
  cryptographic assets.

## Running

```bash
pip install cryptography
python rsa_encryption_demo.py
```

Requires Python 3.10 or newer.

## Expected output

```
=== PostQ Demo Library: RSA-1024 Encryption (classical, broken) ===

[1/4] Generated RSA-1024 keypair
      Algorithm:        RSA
      Key size:         1024 bits
      Public key size:  272 bytes (PEM)
      Private key size: 891 bytes (PEM)
      Generation time:  ~10-30 ms

[2/4] Encrypted message
      Padding:        OAEP / MGF1 / SHA-256
      Ciphertext len: 128 bytes
      Encrypt time:   ~1-3 ms

[3/4] Decrypted ciphertext
      Match:         True

[4/4] Tampered ciphertext decryption
      Result:        REJECTED (ValueError)

=== PostQ Migration Verdict ===
  Algorithm:           RSA-1024
  Quantum exposure:    Critical (Shor's algorithm, polynomial)
  Classical exposure:  Critical (RSA-1024 below NIST minimum)
  Migration target:    ML-KEM-768 (FIPS 203, NIST PQC)
  Hybrid intermediate: X25519 + ML-KEM-768
```

## What PostQ would flag

| Field | Value |
|---|---|
| Algorithm family | Asymmetric, factoring-based |
| Algorithm | RSA |
| Key size | 1024 bits |
| Padding | OAEP / MGF1 / SHA-256 |
| Quantum exposure | Critical (Shor's algorithm) |
| Classical exposure | Critical (sub-quantum factoring feasible) |
| HNDL risk | Severe |
| Recommended migration | ML-KEM-768 (FIPS 203) |
| Hybrid option during transition | X25519 + ML-KEM-768 |

## Note on RSA-1024 plaintext capacity

RSA with OAEP/SHA-256 padding caps plaintext at roughly 62 bytes for
a 1024-bit key. Production systems never use RSA encryption directly
for application data — they wrap a symmetric key (AES) with RSA,
then encrypt the actual payload with the symmetric key. This demo
uses a short message so the encrypt step succeeds; in real-world
patterns the migration to ML-KEM-768 plus AES-GCM is the canonical
target.

## After migration

The matching post-migration example will land at:

```
demo-library/python-mlkem768-encryption/mlkem768_encryption_demo.py
```

Diff the two files for a side-by-side migration walkthrough.

## License

MIT. Educational sample only.
