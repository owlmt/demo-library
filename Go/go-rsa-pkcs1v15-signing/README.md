# go-rsa-pkcs1v15-signing — RSA-2048 + PKCS#1 v1.5 in Go

A self-contained Go program that signs a message with RSA-2048 and
PKCS#1 v1.5 padding using the standard library `crypto/rsa`.

The **"before"** picture for a Go service that signs payloads. Go is
the dominant language for cloud-native infrastructure (Kubernetes
operators, controllers, CI/CD tooling) — this code shape is
everywhere.

## Two findings, not one

This file is deliberately written with PKCS#1 v1.5 padding (the
legacy form) rather than the modern RSASSA-PSS. PostQ flags **two**
distinct issues:

1. RSA itself is quantum-vulnerable — migrate to ML-DSA-65.
2. PKCS#1 v1.5 padding has known weaknesses — use RSASSA-PSS or
   move to ML-DSA-65 directly.

This makes Go the most-flagged single file in the demo set, which
is realistic — legacy Go code is rife with PKCS1v15 patterns.

## Running

```bash
./run.sh
```

Or:

```bash
go run rsa_signing_demo.go
```

Requires Go 1.21+. No external modules — uses only standard library.

## What PostQ would flag

| Field | Value |
|---|---|
| Language | Go |
| Algorithm | RSA |
| Key size | 2048 bits |
| Padding | PKCS#1 v1.5 (legacy) |
| Hash | SHA-256 |
| Library | Go standard library (`crypto/rsa`) |
| Quantum exposure | Critical |
| Padding exposure | Medium (legacy padding) |
| Migration target | ML-DSA-65 (FIPS 204) |

## After migration

Matching post-migration example will land at:

```
demo-library/go-mldsa65-signing/rsa_signing_demo.go
```

Likely uses Cloudflare's `circl` library or a direct liboqs binding.

## License

MIT. Educational sample only.
