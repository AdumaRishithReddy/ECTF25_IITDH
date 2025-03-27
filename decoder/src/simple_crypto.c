/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include "host_messaging.h"

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext)
{
    Aes ctx;    // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error

    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE)
    {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext)
{
    Aes ctx;    // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE)
    {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

void derive_key(uint8_t *sk, size_t sk_len, uint8_t *iv, uint8_t *derived_key)
{
    if (sk == NULL || iv == NULL || derived_key == NULL)
    {
        printf("Invalid input parameters\n");
        return;
    }

    int ret = wc_PBKDF2(derived_key, sk, sk_len, iv, SALT_LENGTH, ITERATIONS, KEY_LENGTH, WC_SHA256);

    if (ret != 0)
    {
        printf("PBKDF2 key derivation failed! Error code: %d\n", ret);
    }
    else
    {
        printf("PBKDF2 key derived successfully\n");
    }
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out)
{
    // Pass values to hash
    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}

int pem_to_der(const char *pemKey, byte **derKey, int *derSize)
{
    // RsaKey key;
    // int ret;

    // wc_InitRsaKey(&key, NULL);

    // // Try decoding PEM directly
    // ret = wc_RsaPrivateKeyDecodePem((const byte*)pemKey, strlen(pemKey), &key);
    // if (ret != 0) {
    //     printf("PEM decode failed: %d\n", ret);
    //     wc_FreeRsaKey(&key);
    //     return -1;
    // }

    // // Get DER size
    // word32 derSz = 0;
    // ret = wc_RsaKeyToDer(&key, NULL, &derSz);
    // if (ret != LENGTH_ONLY_E) {
    //     wc_FreeRsaKey(&key);
    //     return -1;
    // }

    // // Allocate and convert
    // *derKey = malloc(derSz);
    // ret = wc_RsaKeyToDer(&key, *derKey, &derSz);
    // wc_FreeRsaKey(&key);

    // if (ret < 0) {
    //     free(*derKey);
    //     return -1;
    // }

    // *derSize = derSz;
    return 0;
}

int decrypt_rsa(const uint8_t *der_key, size_t key_size,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t *decrypted, size_t decrypted_size)
{
    RsaKey key;
    word32 idx = 0;
    int ret;
    int decrypted_len;

    // Initialize WolfSSL RSA key
    // wc_InitRsaKey(&key, NULL);

    // Load DER-encoded RSA private key
    ret = wc_RsaPrivateKeyDecode(der_key, &idx, &key, key_size);
    if (ret != 0)
    {
        printf("Key decode failed: %d\n", ret);
        wc_FreeRsaKey(&key);
        return -1;
    }

    // Decrypt data
    decrypted_len = wc_RsaPrivateDecrypt(cipher, cipher_len, decrypted, decrypted_size, &key);
    if (decrypted_len < 0)
    {
        printf("Decryption failed: %d\n", decrypted_len);
        wc_FreeRsaKey(&key);
        return -1;
    }

    // Cleanup
    // wc_FreeRsaKey(&key);
    return decrypted_len; // Return the length of the decrypted data
}
#define MAX_BLOCK_SIZE 1024
int hash_firmware_verify(const byte *fwAddr, word32 fwLen, const byte *sigBuf, word32 sigLen)
{


    wc_Sha256 sha;
    byte hash[WC_SHA256_DIGEST_SIZE];
    int ret;
    ecc_key eccKey;
    word32 inOutIdx;
    byte derSig[72]; // ASN.1 DER signature buffer (max ~72 bytes for SECP256R1)
    word32 derSigLen = sizeof(derSig);

    const byte pubKey[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x14, 0xAA, 0x03, 0x92, 0xF3, 0x07, 0xE1, 0xDC, 0xB7, 0xBD, 0xCE, 0x45, 0x2C, 0x3B, 0x2D, 0x89, 0x40, 0x83, 0x96, 0xDB, 0xAD, 0xFD, 0xE1, 0x5B, 0x8E, 0x46, 0x2A, 0xA8, 0x5E, 0xB8, 0xDC, 0xAB, 0x78, 0xDE, 0x24, 0xD9, 0x83, 0x7B, 0xD0, 0xB4, 0x61, 0xC6, 0xC5, 0xB3, 0x81, 0x95, 0xB1, 0x71, 0x28, 0x10, 0x29, 0xC7, 0x5E, 0x8F, 0x9E, 0x63, 0xF5, 0xB7, 0x21, 0x7F, 0x97, 0xC2, 0x2D, 0x70};

    // 1. Compute SHA-256 hash of firmware
    ret = wc_InitSha256(&sha);
    if (ret != 0)
    {
        print_debug("Init sha failed\n");
        return ret;
    }

    ret = wc_Sha256Update(&sha, fwAddr, fwLen);
    if (ret != 0)
    {
        print_debug("Update sha failed\n");
        wc_Sha256Free(&sha);
        return ret;
    }

    ret = wc_Sha256Final(&sha, hash);
    if (ret != 0)
    {
        print_debug("Final sha failed\n");
        wc_Sha256Free(&sha);
        return ret;
    }

    wc_Sha256Free(&sha);

    // 2. Decode the public key
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(pubKey, &inOutIdx, &eccKey, sizeof(pubKey));
    if (ret != 0)
    {
        print_debug("Public key decode failed\n");
        return ret;
    }

    // 3. Set the curve (SECP256R1)
    ret = wc_ecc_set_curve(&eccKey, 32, ECC_SECP256R1);
    if (ret != 0)
    {
        print_debug("Set curve failed\n");
        wc_ecc_free(&eccKey);
        return ret;
    }

    // 5. Verify the signature
    int verify;
    ret = wc_ecc_verify_hash(derSig, derSigLen, hash, sizeof(hash), &verify, &eccKey);
    if (ret != 0 || verify != 1)
    {
        print_debug("Signature verification failed\n");
        wc_ecc_free(&eccKey);
        return (ret != 0) ? ret : -1; // Return error if verification failed
    }

    wc_ecc_free(&eccKey);
    return 0; // Success
}

#endif
