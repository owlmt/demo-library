# typescript-ecdsa-signing — ECDSA-P256 with Node.js crypto

A self-contained TypeScript script that signs a message with
ECDSA-P256 + SHA-256.

The **"before"** picture for a TypeScript service using elliptic-
curve signatures. ECDSA is widely used in JWT (`ES256`), Web3, and
modern signature pipelines because it produces smaller signatures
than RSA.

## Why this matters — and a common misconception

ECDSA is **NOT safer than RSA** under quantum threat. Both are
broken by Shor's algorithm in polynomial time. The misconception
("we're on EC, we're future-proof") is widespread and worth
flagging in the PostQ output.

## Running

```bash
./run.sh
```

Or:

```bash
npx --yes ts-node ecdsa_signing_demo.ts
```

Requires Node.js 18+. Uses `ts-node` (auto-installed via npx).

## What PostQ would flag

| Field | Value |
|---|---|
| Language | TypeScript / Node.js |
| Algorithm | ECDSA |
| Curve | P-256 (secp256r1) |
| Signature scheme | ECDSA with SHA-256 |
| Library | Node.js built-in `crypto` |
| Quantum exposure | Critical (Shor's breaks ECDLP) |
| Migration target | ML-DSA-65 (FIPS 204) |

## After migration

Matching post-migration example will land at:

```
demo-library/typescript-mldsa65-signing/mldsa65_signing_demo.ts
```

## License

MIT. Educational sample only.
