/*
 * rsa_signing_demo.js — RSA-2048 with SHA-256 digital signature using Node.js
 * built-in `crypto` module.
 *
 * The "before" picture for a typical PostQ migration on a Node.js
 * service: an API that signs JWTs, webhooks, or audit logs with
 * RSA-2048. Pattern is everywhere — Auth0, AWS Cognito, custom
 * issuance services, you name it.
 *
 * What PostQ would flag:
 *   - Algorithm:          RSA (asymmetric, factoring-based)
 *   - Key size:           2048 bits
 *   - Quantum exposure:   Critical (Shor's algorithm)
 *   - Migration target:   ML-DSA-65 (FIPS 204)
 *   - Hybrid option:      RSA-2048 + ML-DSA-65 dual-signature
 *
 * Run:  node rsa_signing_demo.js
 *       (no dependencies — uses Node's built-in crypto module)
 *
 * Educational sample only.
 */

"use strict";

const crypto = require("crypto");

const KEY_SIZE_BITS = 2048;
const SIGNATURE_ALGORITHM = "RSA-SHA256";

function main() {
  console.log("=== PostQ Demo Library: RSA-2048 Signing in Node.js (classical) ===");
  console.log();

  // 1. Generate a 2048-bit RSA keypair.
  const t0 = process.hrtime.bigint();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: KEY_SIZE_BITS,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const keyGenMs = Number(process.hrtime.bigint() - t0) / 1e6;

  console.log("[1/4] Generated RSA-" + KEY_SIZE_BITS + " keypair");
  console.log("      Algorithm:        RSA");
  console.log("      Key size:         " + KEY_SIZE_BITS + " bits");
  console.log("      Public key size:  " + publicKey.length + " bytes (PEM)");
  console.log("      Private key size: " + privateKey.length + " bytes (PEM)");
  console.log("      Generation time:  " + keyGenMs.toFixed(1) + " ms");
  console.log();

  // 2. Sign a message.
  const message = "Settle transaction TX-2026-04823 for £1,250,000 to beneficiary 0x4f3a...c2e1";
  const messageBuffer = Buffer.from(message, "utf8");

  const signer = crypto.createSign(SIGNATURE_ALGORITHM);
  signer.update(messageBuffer);
  signer.end();
  const signature = signer.sign(privateKey);

  console.log("[2/4] Signed message");
  console.log("      Message:        " + message);
  console.log("      Signature alg:  " + SIGNATURE_ALGORITHM);
  console.log("      Signature size: " + signature.length + " bytes");
  console.log("      Signature (b64, first 64 chars): " + signature.toString("base64").slice(0, 64) + "...");
  console.log();

  // 3. Verify the signature.
  const verifier = crypto.createVerify(SIGNATURE_ALGORITHM);
  verifier.update(messageBuffer);
  verifier.end();
  const valid = verifier.verify(publicKey, signature);

  console.log("[3/4] Verified signature");
  console.log("      Result:       " + (valid ? "VALID" : "INVALID"));
  console.log();

  // 4. Tampered message.
  const tampered = Buffer.from("Settle transaction TX-2026-04823 for £12,500,000 to beneficiary 0x4f3a...c2e1", "utf8");
  const tamperVerifier = crypto.createVerify(SIGNATURE_ALGORITHM);
  tamperVerifier.update(tampered);
  tamperVerifier.end();
  const tamperedValid = tamperVerifier.verify(publicKey, signature);

  console.log("[4/4] Tampered message verification");
  console.log("      Result:       " + (tamperedValid ? "VALID (UNEXPECTED!)" : "INVALID (expected)"));
  console.log();

  // PostQ migration verdict.
  console.log("=== PostQ Migration Verdict ===");
  console.log();
  console.log("  Algorithm:           RSA-" + KEY_SIZE_BITS);
  console.log("  Quantum exposure:    Critical (Shor's algorithm, polynomial)");
  console.log("  HNDL risk:           High");
  console.log("  Migration target:    ML-DSA-65 (FIPS 204, NIST PQC)");
  console.log("  Hybrid intermediate: RSA-2048 + ML-DSA-65 dual-signature");
  console.log();
  console.log("  Compare with:        javascript-mldsa65-signing/mldsa65_signing_demo.js");
  console.log();
}

main();
