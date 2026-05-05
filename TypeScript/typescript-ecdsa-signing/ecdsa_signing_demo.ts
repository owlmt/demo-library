/**
 * ecdsa_signing_demo.ts — ECDSA-P256 with SHA-256 digital signature
 * using Node.js built-in crypto module.
 *
 * The "before" picture for a TypeScript service that uses elliptic-
 * curve signatures. Pattern is everywhere in Web3, JWT (ES256), and
 * any service that wants smaller signatures than RSA delivers.
 *
 * What PostQ would flag:
 *   - Algorithm:          ECDSA (asymmetric, discrete-log on elliptic curve)
 *   - Curve:              P-256 (secp256r1 / prime256v1)
 *   - Quantum exposure:   Critical (Shor's algorithm breaks ECDLP)
 *   - Migration target:   ML-DSA-65 (FIPS 204) or hybrid ECDSA + ML-DSA-65
 *
 * Distinct from the RSA case: ECDSA is in a different algorithmic
 * family (discrete-log, not factoring), but Shor's algorithm breaks
 * BOTH families. Investors and CISOs sometimes assume "we're on EC,
 * we're safer" — the truth is the quantum threat applies equally.
 *
 * Run:  npx ts-node ecdsa_signing_demo.ts
 *       OR: tsc ecdsa_signing_demo.ts && node ecdsa_signing_demo.js
 */

import * as crypto from "crypto";

const CURVE = "P-256";              // also known as secp256r1 / prime256v1
const SIGNATURE_HASH = "sha256";

function main(): void {
  console.log("=== PostQ Demo Library: ECDSA-P256 Signing in TypeScript (classical) ===");
  console.log();

  // 1. Generate an ECDSA P-256 keypair.
  const t0 = process.hrtime.bigint();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: CURVE,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const keyGenMs = Number(process.hrtime.bigint() - t0) / 1e6;

  console.log(`[1/4] Generated ECDSA keypair`);
  console.log(`      Algorithm:        ECDSA`);
  console.log(`      Curve:            ${CURVE}`);
  console.log(`      Public key size:  ${publicKey.length} bytes (PEM)`);
  console.log(`      Private key size: ${privateKey.length} bytes (PEM)`);
  console.log(`      Generation time:  ${keyGenMs.toFixed(1)} ms`);
  console.log();

  // 2. Sign a message.
  const message: string = "Settle transaction TX-2026-04823 for £1,250,000 to beneficiary 0x4f3a...c2e1";
  const messageBuffer: Buffer = Buffer.from(message, "utf8");

  const signer = crypto.createSign(SIGNATURE_HASH);
  signer.update(messageBuffer);
  signer.end();
  const signature: Buffer = signer.sign(privateKey);

  console.log(`[2/4] Signed message`);
  console.log(`      Message:        ${message}`);
  console.log(`      Signature hash: ${SIGNATURE_HASH}`);
  console.log(`      Signature size: ${signature.length} bytes (DER-encoded)`);
  console.log(`      Signature (b64, first 64 chars): ${signature.toString("base64").slice(0, 64)}...`);
  console.log();

  // 3. Verify the signature.
  const verifier = crypto.createVerify(SIGNATURE_HASH);
  verifier.update(messageBuffer);
  verifier.end();
  const valid: boolean = verifier.verify(publicKey, signature);

  console.log(`[3/4] Verified signature`);
  console.log(`      Result:       ${valid ? "VALID" : "INVALID"}`);
  console.log();

  // 4. Tampered message.
  const tampered: Buffer = Buffer.from(
    "Settle transaction TX-2026-04823 for £12,500,000 to beneficiary 0x4f3a...c2e1",
    "utf8"
  );
  const tamperVerifier = crypto.createVerify(SIGNATURE_HASH);
  tamperVerifier.update(tampered);
  tamperVerifier.end();
  const tamperedValid: boolean = tamperVerifier.verify(publicKey, signature);

  console.log(`[4/4] Tampered message verification`);
  console.log(`      Result:       ${tamperedValid ? "VALID (UNEXPECTED!)" : "INVALID (expected)"}`);
  console.log();

  // PostQ migration verdict.
  console.log("=== PostQ Migration Verdict ===");
  console.log();
  console.log(`  Algorithm:           ECDSA-${CURVE}`);
  console.log(`  Quantum exposure:    Critical (Shor's algorithm breaks ECDLP)`);
  console.log(`  HNDL risk:           High — ECDSA is NOT safer than RSA`);
  console.log(`                       under quantum threat. Common`);
  console.log(`                       misconception worth flagging.`);
  console.log(`  Migration target:    ML-DSA-65 (FIPS 204, NIST PQC)`);
  console.log(`  Hybrid intermediate: ECDSA-P256 + ML-DSA-65 dual-signature`);
  console.log();
  console.log(`  Compare with:        typescript-mldsa65-signing/mldsa65_signing_demo.ts`);
  console.log();
}

main();
