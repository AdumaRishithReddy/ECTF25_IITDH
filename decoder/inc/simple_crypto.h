/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */
#define WOLFSSL_USE_OPTIONS_H
// #if CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H
#endif

#define WOLFSSL_NO_INT128

#include <wolfssl/wolfssl/options.h>
#include "wolfssl/wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfssl/wolfcrypt/hash.h"
#include <wolfssl/wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfssl/wolfcrypt/random.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h> // For Base64_Decode
#include <string.h>

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 16
#define HASH_SIZE MD5_DIGEST_SIZE
#define DER_SIZE 2048
#define RSA_KEY_SIZE 2048 // RSA 2048-bit key
#define RSA_PEM_SIZE 2048

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
int encrypt_sym(const uint8_t *plaintext, const size_t len, const uint8_t *key, uint8_t *ciphertext);


    /** @brief Decrypts ciphertext using a symmetric cipher
     *
     * @param ciphertext A pointer to a buffer of length len containing the
     *           ciphertext to decrypt
     * @param len The length of the ciphertext to decrypt. Must be a multiple of
     *           BLOCK_SIZE (16 bytes)
     * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
     *           the key to use for decryption
     * @param plaintext A pointer to a buffer of length len where the resulting
     *           plaintext will be written to
     *
     * @return 0 on success, -1 on bad length, other non-zero for other error
     */
    int
    decrypt_sym(const uint8_t *ciphertext, const size_t len, const uint8_t *key, uint8_t *plaintext);

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(const void *data, const size_t len, uint8_t *hash_out);

/**
 * @brief Decrypts data using RSA asymmetric decryption.

 * @param cipher A pointer to the buffer containing the ciphertext to decrypt.
 * @param cipher_len The length of the ciphertext buffer.
 * @param der_key A pointer to the DER-encoded RSA private key.
 * @param key_size The size of the DER-encoded key in bytes.
 * @param decr_out_buf A pointer to the buffer where the decrypted data will be stored.
 * @param decr_out_buf_size The size of the output buffer in bytes.
 *
 * @return On success, returns the length of the decrypted data; on error, returns -1.
 */
int decrypt_asym_rsa(const uint8_t *der_key, const size_t key_size,
                     const uint8_t *cipher, const size_t cipher_len,
                     uint8_t *decrypted, const size_t decrypted_size);

// #endif // CRYPTO_EXAMPLE
// #endif // ECTF_CRYPTO_H
