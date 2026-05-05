# c-3des-cbc-encryption — 3DES-CBC with OpenSSL in C

A self-contained C program that encrypts a message with Triple-DES
(3DES, formally TDES, also called DES-EDE3) in CBC mode using
OpenSSL's EVP API.

The **"before"** picture for legacy C codebases. 3DES was widely
deployed in payment systems, ATM networks, government infrastructure,
and embedded devices from the 1990s through the 2010s. **NIST
formally retired 3DES on December 31, 2023.** Anything still using
it today is non-compliant.

## Why this matters most

PostQ's reach into legacy infrastructure is the differentiator
hyperscaler PQC tools cannot match. Cloud-native PQC primitives
ship for new applications; *finding 3DES in a 20-year-old C codebase
running on a payment terminal* is what enterprises actually need.
This file represents the upper bound of "legacy crypto we have to
migrate before quantum is even relevant."

## Running

Requires `libssl-dev` (Ubuntu) or `openssl@3` (macOS) plus a C
compiler.

```bash
./run.sh
```

Or:

```bash
cc -O2 -Wall -o 3des_cbc_demo 3des_cbc_demo.c -lssl -lcrypto
./3des_cbc_demo
```

**Note on OpenSSL 3.x:** newer OpenSSL builds may have 3DES disabled
or deprecated. If you see "EVP_EncryptFinal_ex failed (3DES may be
disabled in your OpenSSL build)", the algorithm is not available in
your linked OpenSSL — which itself reinforces the point: 3DES is
being actively phased out by the toolchain. To enable it for the
demo, run with: `OPENSSL_CONF=/etc/ssl/openssl-legacy.cnf` or build
OpenSSL with the legacy provider.

## What PostQ would flag

| Field | Value |
|---|---|
| Language | C |
| Algorithm | 3DES (Triple-DES, EDE3) |
| Key size | 168 bits effective |
| Mode | CBC with PKCS#5 padding |
| Library | OpenSSL EVP |
| Status | **RETIRED by NIST** |
| Quantum exposure | Severe (Grover → ~56 bits effective) |
| Classical exposure | Critical (formally retired) |
| Migration target | AES-256-GCM |

## On 3DES specifically

3DES applies the DES algorithm three times with different keys.
Despite the 168-bit key length, meet-in-the-middle attacks reduce
effective security to ~112 bits classically. Grover's algorithm
brings that to ~56 bits in the post-quantum era — practically
breakable by anyone with sustained quantum compute.

NIST SP 800-131A explicitly disallowed 3DES for encryption after
December 31, 2023. Any production code still using it is in
violation of FIPS 140-3 and should be migrated immediately.

## After migration

Matching post-migration example will land at:

```
demo-library/c-aes256-gcm-encryption/aes256_gcm_demo.c
```

## License

MIT. Educational sample only — and 3DES is RETIRED. Do not use this
in any new code under any circumstances.
