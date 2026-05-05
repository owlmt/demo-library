# ============================================================================
# Colab → owlmt/demo-library : add the Python RSA-1024 demo
# ============================================================================
#
# Paste these cells into a Google Colab notebook one at a time, top to bottom.
# Each cell is wrapped in `# === CELL N ===` markers so you know where to
# split.
#
# Goal: clone the repo, add the new python-rsa-encryption/ folder with three
# files, commit, push back to GitHub on the main branch.
#
# Prerequisites you handle outside the notebook:
#   1. A GitHub fine-grained personal access token (FGPAT) with:
#        - Resource owner: owlmt
#        - Repository access: Only owlmt/demo-library
#        - Permissions: Contents = Read and Write, Metadata = Read
#        - Expiration: 30 days
#      Mint at https://github.com/settings/personal-access-tokens/new
#
#   2. NEVER paste the PAT into the notebook source. Always use Colab's
#      "Secrets" panel (left sidebar, key icon) or getpass() at runtime,
#      both of which keep the value out of the notebook history.
#
# ============================================================================


# === CELL 1 — Configure your identity and load the PAT securely =============

import os
from getpass import getpass

# Your GitHub username (the account that owns the PAT). Owner of the
# `owlmt/demo-library` repo, presumably this is you.
GITHUB_USERNAME = "owlmt"

# Email used in the commit. GitHub requires it to match your account
# or be one of your verified emails to count toward your contribution
# graph; otherwise the commit lands but is shown as a non-attributed
# author.
GITHUB_EMAIL = "your-email@example.com"   # ← edit this

# The token. We use getpass() so the value is read at runtime and never
# appears in the notebook source. Type or paste at the prompt — your
# input is hidden.
GITHUB_PAT = getpass("Paste your GitHub fine-grained PAT (input hidden): ")

# Sanity check the shape — fine-grained PATs start with `github_pat_`.
assert GITHUB_PAT.startswith("github_pat_") or GITHUB_PAT.startswith("ghp_"), \
    "That doesn't look like a GitHub PAT. Expected prefix github_pat_ or ghp_."

print(f"PAT loaded ({len(GITHUB_PAT)} chars). Username: {GITHUB_USERNAME}.")


# === CELL 2 — Clone owlmt/demo-library ======================================

import subprocess
import os

REPO_OWNER = "owlmt"
REPO_NAME = "demo-library"
WORKDIR = f"/content/{REPO_NAME}"

# Build an authenticated clone URL. The PAT goes in the URL only for this
# one shell call; we rewrite the remote afterward to keep the token out
# of git's saved config.
clone_url = f"https://{GITHUB_USERNAME}:{GITHUB_PAT}@github.com/{REPO_OWNER}/{REPO_NAME}.git"

# If a previous run left a directory, remove it.
if os.path.isdir(WORKDIR):
    subprocess.run(["rm", "-rf", WORKDIR], check=True)

subprocess.run(["git", "clone", clone_url, WORKDIR], check=True)

# Rewrite the origin URL to the un-authenticated form so the token is
# not stored in .git/config. We'll add the token back per push call.
subprocess.run(
    ["git", "-C", WORKDIR, "remote", "set-url", "origin",
     f"https://github.com/{REPO_OWNER}/{REPO_NAME}.git"],
    check=True,
)

# Set the local commit identity.
subprocess.run(["git", "-C", WORKDIR, "config", "user.name", GITHUB_USERNAME], check=True)
subprocess.run(["git", "-C", WORKDIR, "config", "user.email", GITHUB_EMAIL], check=True)

print(f"Cloned to {WORKDIR}")
subprocess.run(["ls", "-la", WORKDIR], check=True)


# === CELL 3 — Write the Python demo files ===================================

import os

DEMO_DIR = os.path.join(WORKDIR, "python-rsa-encryption")
os.makedirs(DEMO_DIR, exist_ok=True)

DEMO_PY = '''"""
rsa_encryption_demo.py — RSA-1024 with OAEP padding for message encryption.

This is the "before" picture for a PostQ migration on the encryption
side: a service that wraps a sensitive payload with RSA-1024.

What PostQ would flag:
  - Algorithm:          RSA (asymmetric, factoring-based)
  - Key size:           1024 bits  (BELOW NIST minimum of 2048)
  - Quantum exposure:   Critical (Shor's algorithm, polynomial)
  - Classical exposure: Critical (sub-quantum factoring feasible)
  - Migration target:   ML-KEM-768 (FIPS 203)
  - Hybrid option:      X25519 + ML-KEM-768

Run:  python rsa_encryption_demo.py
      (requires: pip install cryptography)
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

    # NOTE: RSA-1024 with OAEP/SHA-256 wraps at most ~62 bytes of plaintext.
    # Production systems wrap a symmetric key (AES) with RSA, then encrypt
    # the actual payload symmetrically. We use a short message so the demo
    # runs end-to-end.
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

    tampered = bytearray(ciphertext)
    tampered[10] ^= 0xFF
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

    print("=== PostQ Migration Verdict ===")
    print()
    print(f"  Algorithm:           RSA-{KEY_SIZE_BITS}")
    print( "  Quantum exposure:    Critical (Shor's algorithm, polynomial)")
    print( "  Classical exposure:  Critical (RSA-1024 below NIST minimum)")
    print( "  Migration target:    ML-KEM-768 (FIPS 203, NIST PQC)")
    print( "  Hybrid intermediate: X25519 + ML-KEM-768 during transition")
    print()


if __name__ == "__main__":
    main()
'''

DEMO_README = '''# python-rsa-encryption — RSA-1024 with OAEP padding

A small Python program that generates a 1024-bit RSA keypair, encrypts a
message with OAEP/SHA-256 padding, decrypts it, and demonstrates that a
tampered ciphertext fails decryption.

The "before" picture for a PostQ migration on the encryption side.

## Why this matters

RSA-1024 is already broken for any production use. NIST disallowed it
in 2013. FIPS 140-3 requires minimum 2048. Independent of quantum,
sustained classical compute can factor 1024-bit RSA in offline
analysis.

## Running

```bash
pip install -r requirements.txt
python rsa_encryption_demo.py
```

Requires Python 3.10+.

## What PostQ would flag

| Field | Value |
|---|---|
| Algorithm | RSA |
| Key size | 1024 bits |
| Padding | OAEP / MGF1 / SHA-256 |
| Quantum exposure | Critical |
| Classical exposure | Critical (sub-NIST-minimum) |
| Migration target | ML-KEM-768 (FIPS 203) |

## License

MIT. Educational sample only.
'''

DEMO_REQUIREMENTS = "cryptography>=42.0.0\n"

with open(os.path.join(DEMO_DIR, "rsa_encryption_demo.py"), "w") as f:
    f.write(DEMO_PY)

with open(os.path.join(DEMO_DIR, "README.md"), "w") as f:
    f.write(DEMO_README)

with open(os.path.join(DEMO_DIR, "requirements.txt"), "w") as f:
    f.write(DEMO_REQUIREMENTS)

print(f"Wrote 3 files to {DEMO_DIR}")
subprocess.run(["ls", "-la", DEMO_DIR], check=True)


# === CELL 4 — Test that the demo actually runs in this Colab ================

# Install the dependency in the Colab runtime.
import sys
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "cryptography>=42.0.0"], check=True)

# Run the demo.
subprocess.run([sys.executable, os.path.join(DEMO_DIR, "rsa_encryption_demo.py")], check=True)


# === CELL 5 — Commit and push to GitHub =====================================

# Re-add the PAT to the push URL only for the push call; restore the
# clean URL afterward so the token does not persist in git config.
push_url = f"https://{GITHUB_USERNAME}:{GITHUB_PAT}@github.com/{REPO_OWNER}/{REPO_NAME}.git"

subprocess.run(["git", "-C", WORKDIR, "add", "python-rsa-encryption/"], check=True)
subprocess.run(
    ["git", "-C", WORKDIR, "commit", "-m",
     "demo-library: python-rsa-encryption — RSA-1024 baseline (before-PQC)"],
    check=True,
)

# Use the temporary authenticated push URL.
subprocess.run(
    ["git", "-C", WORKDIR, "push", push_url, "main"],
    check=True,
)

print("Pushed successfully.")
print(f"Visit: https://github.com/{REPO_OWNER}/{REPO_NAME}/tree/main/python-rsa-encryption")


# === CELL 6 — Cleanup (optional but recommended) ============================

# Forget the PAT in this kernel session.
GITHUB_PAT = None
import gc
gc.collect()

# When you're fully done, also revoke the PAT at:
#   https://github.com/settings/personal-access-tokens
# The 30-day expiration is the natural backstop, but revoking explicitly
# is best practice — the token has Contents:Write access, which is more
# than read-only.

print("PAT cleared from kernel memory.")
print("REMINDER: revoke the PAT at https://github.com/settings/personal-access-tokens")
