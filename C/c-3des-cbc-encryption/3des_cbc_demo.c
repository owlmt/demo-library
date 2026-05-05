/*
 * 3des_cbc_demo.c — Triple-DES (3DES) CBC encryption with OpenSSL.
 *
 * The "before" picture for a legacy C codebase using deprecated
 * symmetric encryption. 3DES (also called TDES, DES-EDE3) was
 * widely deployed in financial systems, payment terminals, ATM
 * networks, and government infrastructure from the 1990s through
 * the 2010s. NIST formally retired 3DES on December 31, 2023.
 *
 * What PostQ would flag:
 *   - Algorithm:          3DES (Triple-DES, EDE3)
 *   - Key size:           168 bits (effective 112 bits due to
 *                                   meet-in-the-middle attacks)
 *   - Mode:               CBC (no integrity, padding oracle)
 *   - Status:             RETIRED by NIST since 2023-12-31
 *   - Quantum exposure:   Reduced (Grover further halves effective
 *                                  security to ~56 bits — broken)
 *   - Migration target:   AES-256-GCM (FIPS-approved AEAD)
 *
 * The C/OpenSSL pattern is the canonical "you'll find this in old
 * codebases" example. Shows PostQ's reach into legacy infrastructure
 * the rest of the industry has forgotten about.
 *
 * Run:  ./run.sh
 *       (requires libssl-dev or equivalent)
 *
 * Educational sample only. Do NOT use 3DES in any new code — it's
 * formally retired by NIST and prohibited for federal use.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE_BYTES 24      /* 192 bits, 168 effective for 3DES */
#define IV_SIZE_BYTES   8      /* 3DES uses an 8-byte IV (DES block) */
#define BLOCK_SIZE      8

static void hex_dump(const char *label, const unsigned char *data, size_t len) {
    printf("      %s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}

int main(void) {
    printf("=== PostQ Demo Library: 3DES-CBC Encryption in C with OpenSSL (RETIRED) ===\n");
    printf("\n");

    /* 1. Generate a fresh 3DES key + IV. */
    unsigned char key[KEY_SIZE_BYTES];
    unsigned char iv[IV_SIZE_BYTES];

    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "RAND_bytes failed for key\n");
        return 1;
    }
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "RAND_bytes failed for IV\n");
        return 1;
    }

    printf("[1/4] Generated 3DES key + CBC IV\n");
    printf("      Algorithm:        3DES (Triple-DES, EDE3)\n");
    printf("      Key size:         %d bits (168 effective)\n", KEY_SIZE_BYTES * 8);
    printf("      Mode:             CBC with PKCS#5 padding\n");
    printf("      Status:           RETIRED by NIST since 2023-12-31\n");
    hex_dump("Key (hex)        ", key, sizeof(key));
    hex_dump("IV (hex)         ", iv, sizeof(iv));
    printf("\n");

    /* 2. Encrypt a message. */
    const char *plaintext_str = "Settle TX-2026-04823 confidential";
    size_t plaintext_len = strlen(plaintext_str);
    unsigned char ciphertext[256];
    int ciphertext_len = 0;
    int outlen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); return 1; }

    if (EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen,
                          (const unsigned char *)plaintext_str, plaintext_len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len = outlen;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed (3DES may be disabled in your OpenSSL build)\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);

    printf("[2/4] Encrypted message\n");
    printf("      Plaintext:      \"%s\" (%zu bytes)\n", plaintext_str, plaintext_len);
    printf("      Ciphertext len: %d bytes\n", ciphertext_len);
    hex_dump("Ciphertext (hex) ", ciphertext, (size_t)ciphertext_len);
    printf("\n");

    /* 3. Decrypt. */
    unsigned char decrypted[256];
    int decrypted_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    if (EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    decrypted_len = outlen;
    if (EVP_DecryptFinal_ex(ctx, decrypted + outlen, &outlen) != 1) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    decrypted_len += outlen;
    decrypted[decrypted_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    printf("[3/4] Decrypted ciphertext\n");
    printf("      Recovered:    \"%s\"\n", decrypted);
    printf("      Match:        %s\n", strcmp((const char *)decrypted, plaintext_str) == 0 ? "true" : "false");
    printf("\n");

    /* 4. CBC has no integrity check — tampered ciphertext "decrypts" to garbage
     *    but isn't rejected. Demonstrating the integrity gap. */
    unsigned char tampered_ct[256];
    memcpy(tampered_ct, ciphertext, ciphertext_len);
    tampered_ct[4] ^= 0xFF;

    unsigned char tampered_pt[256];
    int tampered_len = 0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, tampered_pt, &outlen, tampered_ct, ciphertext_len);
    tampered_len = outlen;
    int final_ok = EVP_DecryptFinal_ex(ctx, tampered_pt + outlen, &outlen);
    tampered_len += outlen;
    tampered_pt[tampered_len < 256 ? tampered_len : 255] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    printf("[4/4] Tampered ciphertext decryption\n");
    if (final_ok == 1) {
        printf("      Result:       DECRYPTED — but plaintext is corrupted!\n");
        printf("      Output:       \"%s\"\n", tampered_pt);
        printf("      ↑ CBC has no built-in integrity check.\n");
        printf("        AES-GCM would have rejected this with auth-tag failure.\n");
    } else {
        printf("      Result:       REJECTED (padding error after tamper)\n");
        printf("      ↑ Padding-oracle leakage — CBC's other weakness.\n");
    }
    printf("\n");

    /* PostQ migration verdict. */
    printf("=== PostQ Migration Verdict ===\n");
    printf("\n");
    printf("  Algorithm:           3DES (Triple-DES, EDE3)\n");
    printf("  Status:              RETIRED by NIST since 2023-12-31\n");
    printf("  Quantum exposure:    Severe (Grover halves effective to ~56 bits)\n");
    printf("  Classical exposure:  Critical (algorithm formally retired)\n");
    printf("  HNDL risk:           Severe — anything 3DES-encrypted today\n");
    printf("                       is already considered breakable by\n");
    printf("                       sustained classical compute.\n");
    printf("  Migration target:    AES-256-GCM (FIPS-approved AEAD)\n");
    printf("  Hybrid intermediate: N/A — symmetric, no hybrid needed\n");
    printf("\n");
    printf("  Compare with:        c-aes256-gcm-encryption/aes256_gcm_demo.c\n");
    printf("\n");

    return 0;
}
