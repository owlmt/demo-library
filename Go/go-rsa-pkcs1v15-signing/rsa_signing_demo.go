// Package main demonstrates RSA-PKCS1v15 signing with SHA-256 in Go.
//
// This is the "before" picture for a Go service that signs payloads
// using RSA. Go's standard library crypto/rsa is the most common
// pattern in cloud-native infrastructure code (Kubernetes operators,
// CI/CD pipelines, infrastructure controllers).
//
// What PostQ would flag:
//   - Algorithm:          RSA (asymmetric, factoring-based)
//   - Key size:           2048 bits
//   - Padding:            PKCS#1 v1.5 (legacy; RSASSA-PSS preferred)
//   - Quantum exposure:   Critical (Shor's algorithm)
//   - Padding exposure:   Medium (PKCS#1 v1.5 has known weaknesses;
//                                 PSS is the modern recommendation
//                                 even before PQC migration)
//   - Migration target:   ML-DSA-65 (FIPS 204)
//   - Hybrid option:      RSA-2048 + ML-DSA-65 dual-signature
//
// Note: this file deliberately uses PKCS#1 v1.5 padding to demonstrate
// PostQ flagging two distinct issues on the same line: quantum
// vulnerability AND legacy padding scheme. Real Go services should
// use rsa.SignPSS / rsa.VerifyPSS even before PQC migration.
//
// Run: go run rsa_signing_demo.go
//      (no go.mod needed — uses only standard library)
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

const (
	keySizeBits = 2048
)

func main() {
	fmt.Println("=== PostQ Demo Library: RSA-PKCS1v15 Signing in Go (classical) ===")
	fmt.Println()

	// 1. Generate a 2048-bit RSA keypair.
	t0 := time.Now()
	privateKey, err := rsa.GenerateKey(rand.Reader, keySizeBits)
	if err != nil {
		fmt.Printf("ERROR generating key: %v\n", err)
		return
	}
	keyGenMs := time.Since(t0).Milliseconds()
	publicKey := &privateKey.PublicKey

	fmt.Printf("[1/4] Generated RSA-%d keypair\n", keySizeBits)
	fmt.Printf("      Algorithm:        RSA\n")
	fmt.Printf("      Key size:         %d bits\n", keySizeBits)
	fmt.Printf("      Modulus length:   %d bytes\n", publicKey.Size())
	fmt.Printf("      Generation time:  %d ms\n", keyGenMs)
	fmt.Println()

	// 2. Sign a message with PKCS#1 v1.5 padding.
	message := "Settle transaction TX-2026-04823 for £1,250,000 to beneficiary 0x4f3a...c2e1"
	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Printf("ERROR signing: %v\n", err)
		return
	}

	fmt.Printf("[2/4] Signed message\n")
	fmt.Printf("      Message:        %s\n", message)
	fmt.Printf("      Padding:        PKCS#1 v1.5 (legacy)\n")
	fmt.Printf("      Hash:           SHA-256\n")
	fmt.Printf("      Signature size: %d bytes\n", len(signature))
	fmt.Printf("      Signature (b64, first 64 chars): %s...\n",
		base64.StdEncoding.EncodeToString(signature)[:64])
	fmt.Println()

	// 3. Verify the signature.
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	valid := err == nil

	fmt.Printf("[3/4] Verified signature\n")
	if valid {
		fmt.Printf("      Result:       VALID\n")
	} else {
		fmt.Printf("      Result:       INVALID (%v)\n", err)
	}
	fmt.Println()

	// 4. Tampered message.
	tampered := "Settle transaction TX-2026-04823 for £12,500,000 to beneficiary 0x4f3a...c2e1"
	tamperedHash := sha256.Sum256([]byte(tampered))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, tamperedHash[:], signature)

	fmt.Printf("[4/4] Tampered message verification\n")
	if err == nil {
		fmt.Printf("      Result:       VALID (UNEXPECTED!)\n")
	} else {
		fmt.Printf("      Result:       INVALID (expected) — %v\n", err)
	}
	fmt.Println()

	// PostQ migration verdict.
	fmt.Println("=== PostQ Migration Verdict ===")
	fmt.Println()
	fmt.Printf("  Algorithm:           RSA-%d\n", keySizeBits)
	fmt.Printf("  Padding:             PKCS#1 v1.5 (legacy — also flagged)\n")
	fmt.Printf("  Quantum exposure:    Critical (Shor's algorithm)\n")
	fmt.Printf("  Padding exposure:    Medium (use RSASSA-PSS even before PQC)\n")
	fmt.Printf("  HNDL risk:           High\n")
	fmt.Printf("  Migration target:    ML-DSA-65 (FIPS 204, NIST PQC)\n")
	fmt.Printf("  Hybrid intermediate: RSA-2048 + ML-DSA-65 dual-signature\n")
	fmt.Println()
	fmt.Printf("  Compare with:        go-mldsa65-signing/rsa_signing_demo.go\n")
	fmt.Println()
}
