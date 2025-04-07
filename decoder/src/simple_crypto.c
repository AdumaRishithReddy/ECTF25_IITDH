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

void Initialize_ECC(ecc_key *eccKey)
{
    wc_ecc_init(eccKey);
    const byte eccPubKeyDer[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0x73, 0x04, 0xd8, 0x7f, 0xcc, 0x9a, 0x8c, 0xa4, 0x09, 0xf8, 0x52, 0xbc,
        0x19, 0x1e, 0xd2, 0x2d, 0x11, 0x09, 0x03, 0x5f, 0xd4, 0xdc, 0xfb, 0x3f, 0xb6,
        0xc2, 0x1a, 0xb1, 0x27, 0xec, 0xa1, 0xfa, 0x57, 0x4d, 0x04, 0x81, 0x47, 0x75,
        0x06, 0x2f, 0x66, 0x87, 0x14, 0x3f, 0x72, 0x32, 0x10, 0x9d, 0x70, 0x39, 0x4c,
        0x7b, 0x76, 0x18, 0x23, 0x07, 0x8a, 0xa4, 0x5a, 0x1a, 0xc7, 0x32, 0xc2, 0x3c};
    const word32 eccPubKeyDerLen = sizeof(eccPubKeyDer);

    // Parse ASN.1 DER key
    word32 idx = 0;
    int ret;
    ret = wc_EccPublicKeyDecode(eccPubKeyDer, &idx, eccKey, eccPubKeyDerLen);
    if (ret != 0)
    {
        print_debug("Failed to decode ASN.1 DER key\n");
        wc_ecc_free(eccKey);
        // return ret;
    }

    // Verify key is valid
    ret = wc_ecc_check_key(eccKey);
    if (ret != 0)
    {
        print_debug("Imported key is invalid\n");
        wc_ecc_free(eccKey);
        // return ret;
    }
    else
    {
        print_debug("Imported key is valid\n");
    }
}
int hash_firmware_verify(const byte *fwAddr, word32 fwLen,
                         const byte *sigBuf, word32 sigLen, ecc_key *eccKey)
{

    int ret;
    mp_int mp_r, mp_s;
    mp_init(&mp_r);
    mp_init(&mp_s);
    mp_read_unsigned_bin(&mp_r, sigBuf, 32); // First 32 bytes = r
    mp_read_unsigned_bin(&mp_s, sigBuf + 32, 32);
    int result;
    uint8_t hashres[32];
    hash(fwAddr, fwLen, hashres);
    ret = wc_ecc_verify_hash_ex(&mp_r, &mp_s, hashres, 32, &result, eccKey);
    if (ret < 0)
    {
        char errStr[50];
        sprintf(errStr, "Signature verification failed %d(%s)\n", ret,wc_GetErrorString(ret));
        print_debug(errStr);
    }
    else
    {
        print_debug("Signature verification successful\n");
    }
    return ret;
    // #ifdef WOLFSSL_PUBLIC_MP
    //     print_debug("WOLFSSL_PUBLIC_MP is defined\n");
    // #endif
    //     // mp_init(&mp_s);

    //     char sigHexaft[200]; // Needs to be 2*sigLen + 1 for hex representation
    //     char *ptra = sigHexaft;

    //     ptra += sprintf(ptra, "Raw Signature (%d bytes): ", sigLen);
    //     for (word32 i = 0; i < sigLen; i++)
    //     {
    //         ptra += sprintf(ptra, "%02X", sigBuf[i]);
    //     }
    //     print_debug(sigHexaft);
    //     char fwBuf[200]; // Needs to be 2*sigLen + 1 for hex representation
    //     char *ptrb = fwBuf;

    //     ptrb += sprintf(ptrb, "Raw Signature (%d bytes): ", fwLen);
    //     for (word32 i = 0; i < fwLen; i++)
    //     {
    //         ptrb += sprintf(ptrb, "%02X", fwAddr[i]);
    //     }
    //     print_debug(fwBuf);
    //     ret = wc_ecc_check_key(eccKey);
    //     if (ret != 0)
    //     {
    //         print_debug("Imported key is invalid\n");
    //         wc_ecc_free(eccKey);
    //         // return ret;
    //     }
    //     else
    //     {
    //         print_debug("Imported key is valid\n");
    //     }
    //     ret = wc_SignatureVerify(
    //         WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
    //         fwAddr, fwLen,
    //         sigBuf, sigLen,
    //         eccKey, sizeof(eccKey));
    //     if (ret < 0)
    //     {
    //         char errStr[50];
    //         sprintf(errStr, "Signature verification failed %d\n", ret);
    //         print_debug(errStr);
    //     }
    //     else
    //     {
    //         print_debug("Signature verification successful\n");
    //     }

    //     wc_ecc_free(eccKey);
    //     return ret; // 0 = success, <0 = error
}

#endif
