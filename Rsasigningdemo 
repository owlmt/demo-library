/*
 * RsaSigningDemo — RSA-2048 with SHA-256 digital signature.
 *
 * This is the "before" picture for a typical PostQ migration:
 * a service that signs messages with RSA-2048. RSA-2048 is
 * widely deployed today and considered safe against classical
 * attackers, but Shor's algorithm running on a sufficiently-
 * scaled quantum computer breaks it polynomially. The U.S.
 * National Security Agency CNSA 2.0 timeline requires migration
 * away from RSA for national security systems by 2035, and
 * harvest-now-decrypt-later attackers do not need to wait for
 * that deadline — they only need to record signed payloads
 * today and forge or analyse them later.
 *
 * What PostQ would flag in this file:
 *   - Algorithm:          RSA (asymmetric, factoring-based)
 *   - Key size:           2048 bits
 *   - Quantum exposure:   Critical (Shor's algorithm)
 *   - Recommended migration target:
 *       ML-DSA-65 (FIPS 204), or hybrid RSA-2048 + ML-DSA-65
 *       during transition. Hybrid lets you stay interoperable
 *       with classical-only verifiers while the ecosystem
 *       catches up.
 *
 * The matching "after" file in this library will be
 *   java-mldsa65-signing/MlDsa65SigningDemo.java
 * (ships when the migration example lands). Diff the two for
 * a side-by-side migration walkthrough.
 *
 * Run:  ./run.sh
 *       (or: javac RsaSigningDemo.java && java RsaSigningDemo)
 *
 * Educational sample only. Do not use these key-generation
 * patterns in production — among other things, this demo
 * generates a fresh keypair on every run instead of loading
 * from a keystore, and prints the private key to stdout for
 * pedagogical clarity. A real service would never do either.
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

public class RsaSigningDemo {

    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE_BITS = 2048;

    public static void main(String[] args) throws Exception {
        System.out.println("=== PostQ Demo Library: RSA-2048 Signing (classical) ===");
        System.out.println();

        // 1. Generate a 2048-bit RSA keypair.
        //    PostQ would log this as a vulnerable key generation site,
        //    and the migration backlog would suggest ML-DSA-65
        //    (FIPS 204) as the replacement.
        long t0 = System.nanoTime();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(KEY_SIZE_BITS, SecureRandom.getInstanceStrong());
        KeyPair keyPair = kpg.generateKeyPair();
        long keyGenMs = (System.nanoTime() - t0) / 1_000_000;

        PublicKey publicKey   = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("[1/4] Generated RSA-" + KEY_SIZE_BITS + " keypair");
        System.out.println("      Algorithm:        " + publicKey.getAlgorithm());
        System.out.println("      Public key size:  " + publicKey.getEncoded().length + " bytes");
        System.out.println("      Private key size: " + privateKey.getEncoded().length + " bytes");
        System.out.println("      Generation time:  " + keyGenMs + " ms");
        System.out.println();

        // 2. Sign a message.
        String message = "Settle transaction TX-2026-04823 for £1,250,000 to beneficiary 0x4f3a...c2e1";
        byte[] messageBytes = message.getBytes("UTF-8");

        t0 = System.nanoTime();
        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(privateKey);
        signer.update(messageBytes);
        byte[] signatureBytes = signer.sign();
        long signMs = (System.nanoTime() - t0) / 1_000_000;

        System.out.println("[2/4] Signed message");
        System.out.println("      Message:        " + message);
        System.out.println("      Signature alg:  " + SIGNATURE_ALGORITHM);
        System.out.println("      Signature size: " + signatureBytes.length + " bytes");
        System.out.println("      Sign time:      " + signMs + " ms");
        System.out.println("      Signature (b64, first 64 chars): "
            + Base64.getEncoder().encodeToString(signatureBytes).substring(0, 64) + "...");
        System.out.println();

        // 3. Verify the signature.
        t0 = System.nanoTime();
        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(messageBytes);
        boolean valid = verifier.verify(signatureBytes);
        long verifyMs = (System.nanoTime() - t0) / 1_000_000;

        System.out.println("[3/4] Verified signature");
        System.out.println("      Result:       " + (valid ? "VALID" : "INVALID"));
        System.out.println("      Verify time:  " + verifyMs + " ms");
        System.out.println();

        // 4. Demonstrate that a tampered message fails verification.
        byte[] tamperedBytes = "Settle transaction TX-2026-04823 for £12,500,000 to beneficiary 0x4f3a...c2e1".getBytes("UTF-8");
        Signature tamperVerifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        tamperVerifier.initVerify(publicKey);
        tamperVerifier.update(tamperedBytes);
        boolean tamperedValid = tamperVerifier.verify(signatureBytes);

        System.out.println("[4/4] Tampered message verification");
        System.out.println("      Tampered:     " + new String(tamperedBytes, "UTF-8"));
        System.out.println("      Result:       " + (tamperedValid ? "VALID (UNEXPECTED!)" : "INVALID (expected)"));
        System.out.println();

        // Summary footer with the PostQ migration verdict.
        System.out.println("=== PostQ Migration Verdict ===");
        System.out.println();
        System.out.println("  Algorithm:           RSA-" + KEY_SIZE_BITS);
        System.out.println("  Quantum exposure:    Critical (Shor's algorithm, polynomial)");
        System.out.println("  HNDL risk:           High — signed payloads recorded today");
        System.out.println("                       could be forensically analysed when a");
        System.out.println("                       sufficiently large quantum computer");
        System.out.println("                       reaches scale.");
        System.out.println("  Migration target:    ML-DSA-65 (FIPS 204, NIST PQC)");
        System.out.println("  Hybrid intermediate: RSA-2048 + ML-DSA-65 dual-signature");
        System.out.println();
        System.out.println("  Compare with:        java-mldsa65-signing/MlDsa65SigningDemo.java");
        System.out.println("                       (after-migration version)");
        System.out.println();
    }
}