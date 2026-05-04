# java-rsa-signing — RSA-2048 with SHA-256

A small, self-contained Java program that generates a 2048-bit RSA
keypair, signs a message, verifies the signature, and demonstrates
that a tampered message fails verification.

This is the **"before"** picture for a typical PostQ migration. It
runs today, on every JDK from 11 onward, with no dependencies. It
also represents one of the most common cryptographic patterns in
production: a service signing payloads (transactions, JWT issuance,
software releases, configuration updates) with RSA.

## Why this matters

RSA-2048 is widely deployed and considered safe against classical
attackers. It is **not** safe against a sufficiently scaled quantum
computer running Shor's algorithm, which factors RSA moduli in
polynomial time. NIST has standardized post-quantum replacements:
[FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) is
the recommended target for digital signatures.

PostQ scans codebases like this one and produces:
- A **CBOM** (Cryptographic Bill of Materials) entry recording the
  algorithm, key size, and call sites.
- A **risk score** computed from quantum exposure, business
  criticality, and migration complexity.
- A **migration backlog entry** sequenced against your other
  cryptographic assets.

## Running

```bash
./run.sh
```

Or manually:

```bash
javac RsaSigningDemo.java
java RsaSigningDemo
```

Requires JDK 11 or newer.

## Expected output

```
=== PostQ Demo Library: RSA-2048 Signing (classical) ===

[1/4] Generated RSA-2048 keypair
      Algorithm:        RSA
      Public key size:  294 bytes
      Private key size: 1218 bytes
      Generation time:  ~50-150 ms

[2/4] Signed message
      Message:        Settle transaction TX-2026-04823 for £1,250,000 ...
      Signature alg:  SHA256withRSA
      Signature size: 256 bytes
      Sign time:      ~5-15 ms

[3/4] Verified signature
      Result:       VALID

[4/4] Tampered message verification
      Result:       INVALID (expected)

=== PostQ Migration Verdict ===
  Algorithm:           RSA-2048
  Quantum exposure:    Critical (Shor's algorithm, polynomial)
  Migration target:    ML-DSA-65 (FIPS 204, NIST PQC)
  Hybrid intermediate: RSA-2048 + ML-DSA-65 dual-signature
```

## What PostQ would flag

| Field | Value |
|---|---|
| Algorithm family | Asymmetric, factoring-based |
| Algorithm | RSA |
| Key size | 2048 bits |
| Signature scheme | RSASSA-PKCS1-v1_5 with SHA-256 |
| Quantum exposure | Critical (Shor's algorithm) |
| HNDL risk | High |
| Recommended migration | ML-DSA-65 (FIPS 204) |
| Hybrid option during transition | RSA-2048 + ML-DSA-65 |

## After migration

The matching post-migration example will land in this library at:

```
demo-library/java-mldsa65-signing/MlDsa65SigningDemo.java
```

Diff the two files for a side-by-side migration walkthrough.

## License

MIT. Educational sample only — do not use these key-generation
patterns in production. See the file header comment in
`RsaSigningDemo.java` for specific limitations.