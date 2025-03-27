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
#if CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H
#define KEY_LENGTH 16   // Derived key length
#define ITERATIONS 1000 // Number of PBKDF2 iterations
#define SALT_LENGTH 16
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
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);

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

void derive_key(uint8_t *sk, size_t sk_len, uint8_t *iv, uint8_t *derived_key);

int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);

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
int hash(void *data, size_t len, uint8_t *hash_out);

int pem_to_der(const char *pemKey, byte **derKey, int *derSize);

int decrypt_rsa(const uint8_t* der_key, size_t key_size, 
                const uint8_t* cipher, size_t cipher_len, 
                uint8_t* decrypted, size_t decrypted_size);

int hash_firmware_verify(const byte *fwAddr, word32 fwLen, const byte *sigBuf, word32 sigLen);

#endif // CRYPTO_EXAMPLE
#endif // ECTF_CRYPTO_H
