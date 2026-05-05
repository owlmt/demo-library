# javascript-rsa-signing — RSA-2048 with Node.js crypto

A self-contained Node.js script that signs a message with RSA-2048
+ SHA-256 using the built-in `crypto` module. No external
dependencies.

This is the **"before"** picture for a PostQ migration on a Node.js
service. The pattern matches what you'll find in JWT issuance
services, webhook signers, audit-log signers, and identity
providers.

## Why this matters

RSA-2048 is widely deployed across the JavaScript ecosystem. Every
Auth0-style identity service, every webhook signer, every
artifact-signing pipeline that runs on Node.js touches this code
shape. NIST FIPS 204 (ML-DSA) is the standardized PQC replacement.

## Running

```bash
./run.sh
```

Or:

```bash
node rsa_signing_demo.js
```

Requires Node.js 18 or newer. No `npm install`.

## What PostQ would flag

| Field | Value |
|---|---|
| Language | JavaScript / Node.js |
| Algorithm | RSA |
| Key size | 2048 bits |
| Signature scheme | RSA-PKCS1-v1.5 with SHA-256 |
| Library | Node.js built-in `crypto` |
| Quantum exposure | Critical |
| Migration target | ML-DSA-65 (FIPS 204) |

## After migration

Matching post-migration example will land at:

```
demo-library/javascript-mldsa65-signing/mldsa65_signing_demo.js
```

Likely uses `@noble/post-quantum` or a direct liboqs WASM binding.

## License

MIT. Educational sample only.
