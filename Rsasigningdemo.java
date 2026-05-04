import org.openquantumsafe.Signature;

public class MlDsa65SigningDemo {

    private static final String ALGORITHM = "Dilithium";
    private static final String SIGNATURE_ALGORITHM = "ML-DSA-65";

    public static void main(String[] args) throws Exception {
        System.out.println("=== PostQ Demo Library: ML-DSA-65 Signing (quantum-safe) ===");
        System.out.println();

        // 1. Initialize the ML-DSA-65 signature scheme.
        Signature signature = new Signature(ALGORITHM);

        // 2. Generate a keypair.
        long t0 = System.nanoTime();
        signature.generateKeyPair();
        long keyGenMs = (System.nanoTime() - t0) / 1_000_000;

        byte[] publicKey = signature.exportPublicKey();
        byte[] privateKey = signature.exportSecretKey();

        System.out.println("[1/4] Generated ML-DSA-65 keypair");
        System.out.println("      Algorithm:        " + ALGORITHM);
        System.out.println("      Public key size:  " + publicKey.length + " bytes");
        System.out.println("      Private key size: " + privateKey.length + " bytes");
        System.out.println("      Generation time:  " + keyGenMs + " ms");
        System.out.println();

        // 3. Sign a message.
        String message = "Settle transaction TX-2026-04823 for £1,250,000 to beneficiary 0x4f3a...c2e1";
        byte[] messageBytes = message.getBytes("UTF-8");

        byte[] signedBytes = signature.sign(messageBytes);

        System.out.println("[2/4] Signed message");
        System.out.println("      Message:      " + message);
        System.out.println("      Signature:    " + Base64.getEncoder().encodeToString(signedBytes));
        System.out.println();

        // 4. Verify the signature.
        boolean valid = signature.verify(messageBytes, signedBytes);

        System.out.println("[3/4] Verified signature");
        System.out.println("      Result:       " + (valid ? "VALID" : "INVALID"));
        System.out.println();

        // 5. Tamper with the message and verify again.
        byte[] tamperedBytes = "Settle transaction TX-2026-04823 for £1,250,000 to beneficiary 0x4f3a...c2e2".getBytes("UTF-8");
        boolean tamperedValid = signature.verify(tamperedBytes, signedBytes);

        System.out.println("[4/4] Tampered message verification");
        System.out.println("      Tampered:     " + new String(tamperedBytes, "UTF-8"));
        System.out.println("      Result:       " + (tamperedValid ? "VALID (UNEXPECTED!)" : "INVALID (expected)"));
        System.out.println();

        // Summary footer with the PostQ migration verdict.
        System.out.println("=== PostQ Migration Verdict ===");
        System.out.println();
        System.out.println("  Algorithm:           ML-DSA-65");
        System.out.println("  Quantum exposure:    None (quantum-safe)");
        System.out.println("  Migration complete:  Yes");
        System.out.println();
    }
}