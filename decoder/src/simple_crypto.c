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

#include "wolfssl/wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfssl/wolfcrypt/hash.h"
#include <wolfssl/wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h> // For Base64_Decode
#include <string.h>

#include <stdint.h>
#include <string.h>

#include "simple_crypto.h"
#include "host_messaging.h"

#define MAX_BLOCK_SIZE 1024
#define BLOCK_SIZE 16

/******************************** FUNCTION PROTOTYPES ********************************/
int encrypt_sym(const uint8_t *plaintext, 
                const size_t len, 
                const uint8_t *key, 
                uint8_t *ciphertext)
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




int decrypt_sym(const uint8_t *ciphertext, 
                const size_t len, 
                const uint8_t *key, 
                uint8_t *plaintext)
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



int hash(const void *data, 
        const size_t len, 
        uint8_t *hash_out)
{
    // Pass values to hash
    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}



int decrypt_asym_rsa(const uint8_t *cipher, const size_t cipher_len,
                const uint8_t *der_key, const size_t key_size,
                uint8_t *decr_out_buf, const size_t decr_out_buf_size)
{
    RsaKey key;
    size_t idx = 0;

    // Load DER-encoded RSA private key
    int ret = wc_RsaPrivateKeyDecode(der_key, /*Private Key in DER format*/
                                &idx, /*Start INDEX of DER key*/
                                &key, /* RSA struct to initialize */
                                key_size);
    if (ret != 0) {
        printf("RSA Key decode failed: %d\n", ret);
        wc_FreeRsaKey(&key);
        return -1;
    }

    // Decrypt data
    int decrypted_len = wc_RsaPrivateDecrypt(cipher, cipher_len, decr_out_buf, decr_out_buf_size, &key);
    if (decrypted_len < 0) {
        printf("Decryption failed: %d\n", decrypted_len);
        wc_FreeRsaKey(&key);
        return -1;
    }

    // Cleanup
    wc_FreeRsaKey(&key);

    return decrypted_len; // Return the length of the decrypted data
}