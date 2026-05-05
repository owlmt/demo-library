"""
rsa_encryption_demo.py — RSA-1024 with OAEP padding for message encryption.

This is the "before" picture for a typical PostQ migration on the
encryption-and-key-exchange side: a service that wraps a sensitive
payload with RSA-1024. RSA-1024 has been disallowed by NIST since
2013 and is not compliant with FIPS 140-3 or NSA CNSA 2.0 for any
contemporary deployment. It is also vulnerable to harvest-now-
decrypt-later attacks well before quantum computers reach scale —
a determined adversary with sustained classical compute could
arguably already factor RSA-1024 in offline analysis. Anything
encrypted with RSA-1024 today should be considered exposed.

What PostQ would flag in this file:
  - Algorithm:          RSA (asymmetric, factoring-based)
  - Key size:           1024 bits  (BELOW NIST minimum of 2048)
  - Quantum exposure:   Critical (Shor's algorithm, polynomial)
  - Classical exposure: Critical (sub-quantum factoring is feasible
                                  at 1024-bit; this is broken even
                                  before quantum capability arrives)
  - Recommended migration target:
      ML-KEM-768 (FIPS 203) for the key-encapsulation half, or
      hybrid X25519 + ML-KEM-768 during transition to keep
      interoperability with classical-only systems while the
      ecosystem catches up.

The matching "after" file in this library will be
  python-mlkem768-encryption/mlkem768_encryption_demo.py
(ships when the migration example lands). Diff the two for a
side-by-side migration walkthrough.

Run:  python rsa_encryption_demo.py
      (requires: pip install cryptography)

Educational sample only. Do not use these key-generation patterns
in production. Among other things, this demo generates a fresh
keypair on every run instead of loading from a key store, prints
key material to stdout for pedagogical clarity, and uses RSA-1024
which is already broken. A real service would do none of these.
"""

import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


KEY_SIZE_BITS = 1024            # NIST disallowed since 2013
PUBLIC_EXPONENT = 65537


def main() -> None:
    print("=== PostQ Demo Library: RSA-1024 Encryption (classical, broken) ===")
    print()

    # 1. Generate a 1024-bit RSA keypair.
    #    PostQ would log this as a CRITICAL vulnerable key generation
    #    site. The migration backlog would suggest ML-KEM-768 (FIPS 203)
    #    as the replacement.
    t0 = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    keygen_ms = (time.perf_counter() - t0) * 1000

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    print(f"[1/4] Generated RSA-{KEY_SIZE_BITS} keypair")
    print(f"      Algorithm:        RSA")
    print(f"      Key size:         {KEY_SIZE_BITS} bits")
    print(f"      Public key size:  {len(public_pem)} bytes (PEM)")
    print(f"      Private key size: {len(private_pem)} bytes (PEM)")
    print(f"      Generation time:  {keygen_ms:.1f} ms")
    print()

    # 2. Encrypt a message using RSA-OAEP with SHA-256.
    # NOTE: RSA-1024 with OAEP/SHA-256 padding can wrap at most ~62 bytes
    # of plaintext. This is itself a limitation of using bare RSA encryption
    # for application data — production systems wrap a symmetric key with
    # RSA, then encrypt the actual payload with that symmetric key. We use
    # a short message here purely so the demo runs end-to-end.
    message = b"Settle TX-2026-04823 for confidential payment"

    t0 = time.perf_counter()
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encrypt_ms = (time.perf_counter() - t0) * 1000

    print(f"[2/4] Encrypted message")
    print(f"      Message:        {message.decode('utf-8')}")
    print(f"      Padding:        OAEP / MGF1 / SHA-256")
    print(f"      Ciphertext len: {len(ciphertext)} bytes")
    print(f"      Encrypt time:   {encrypt_ms:.2f} ms")
    print(f"      Ciphertext (b64, first 64 chars):")
    print(f"        {base64.b64encode(ciphertext).decode('ascii')[:64]}...")
    print()

    # 3. Decrypt the ciphertext.
    t0 = time.perf_counter()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    decrypt_ms = (time.perf_counter() - t0) * 1000

    print(f"[3/4] Decrypted ciphertext")
    print(f"      Decrypt time:  {decrypt_ms:.2f} ms")
    print(f"      Recovered:     {plaintext.decode('utf-8')}")
    print(f"      Match:         {plaintext == message}")
    print()

    # 4. Demonstrate that tampering with the ciphertext fails decryption.
    tampered = bytearray(ciphertext)
    tampered[10] ^= 0xFF      # flip one byte mid-ciphertext
    tampered_bytes = bytes(tampered)

    print(f"[4/4] Tampered ciphertext decryption")
    try:
        private_key.decrypt(
            tampered_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print("      Result:        DECRYPTED (UNEXPECTED!)")
    except Exception as exc:
        print(f"      Result:        REJECTED ({type(exc).__name__})")
    print()

    # Summary footer with the PostQ migration verdict.
    print("=== PostQ Migration Verdict ===")
    print()
    print(f"  Algorithm:           RSA-{KEY_SIZE_BITS}")
    print( "  Quantum exposure:    Critical (Shor's algorithm, polynomial)")
    print( "  Classical exposure:  Critical (RSA-1024 below NIST minimum)")
    print( "  HNDL risk:           Severe — payloads encrypted today are")
    print( "                       already at the edge of feasibility for")
    print( "                       offline factoring; quantum capability")
    print( "                       only accelerates the inevitable.")
    print( "  Migration target:    ML-KEM-768 (FIPS 203, NIST PQC)")
    print( "  Hybrid intermediate: X25519 + ML-KEM-768 during transition")
    print()
    print( "  Compare with:        python-mlkem768-encryption/mlkem768_encryption_demo.py")
    print( "                       (after-migration version)")
    print()


if __name__ == "__main__":
    main()
