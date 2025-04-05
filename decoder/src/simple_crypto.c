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
// int hash_firmware_verify(const byte *fwAddr, word32 fwLen, const byte *sigBuf, word32 sigLen)
// {
//     wc_Sha256 sha;
//     byte hash[WC_SHA256_DIGEST_SIZE];
//     int ret;
//     ecc_key eccKey;
//     word32 inOutIdx = 0;
//     int verify;

//     // Extract actual ECC public key (skip ASN.1 headers)
//     const byte pubKeyRaw[] = {
//         0x04, 0x73, 0x04, 0xD8, 0x7F, 0xCC, 0x9A, 0x8C, 0xA4, 0x09,
//         0xF8, 0x52, 0xBC, 0x19, 0x1E, 0xD2, 0x2D, 0x11, 0x09, 0x03,
//         0x5F, 0xD4, 0xDC, 0xFB, 0x3F, 0xB6, 0xC2, 0x1A, 0xB1, 0x27,
//         0xEC, 0xA1, 0xFA, 0x57, 0x4D, 0x04, 0x81, 0x47, 0x75, 0x06,
//         0x2F, 0x66, 0x87, 0x14, 0x3F, 0x72, 0x32, 0x10, 0x9D, 0x70,
//         0x39, 0x4C, 0x7B, 0x76, 0x18, 0x23, 0x07, 0x8A, 0xA4, 0x5A,
//         0x1A, 0xC7, 0x32, 0xC2, 0x3C};

//     // Initialize SHA-256
//     ret = wc_InitSha256(&sha);
//     if (ret != 0)
//     {
//         print_debug("Init sha failed\n");
//         return ret;
//     }

//     // Hash the firmware
//     ret = wc_Sha256Update(&sha, fwAddr, fwLen);
//     if (ret != 0)
//     {
//         print_debug("Update sha failed\n");
//         ret = -1;
//         goto exit;
//     }

//     ret = wc_Sha256Final(&sha, hash);
//     if (ret != 0)
//     {
//         print_debug("Final sha failed\n");
//         ret = -2;
//         goto exit;
//     }

//     // Import public key
//     ret = wc_ecc_import_x963(pubKeyRaw, sizeof(pubKeyRaw), &eccKey);
//     if (ret != 0)
//     {
//         print_debug("Public key import failed\n");
//         ret = -3;
//         goto exit;
//     }

//     // Set curve parameters
//     ret = wc_ecc_set_curve(&eccKey, 32, ECC_SECP256R1);
//     if (ret != 0)
//     {
//         print_debug("Set curve failed\n");
//         ret = -4;
//         goto exit;
//     }

//     // Convert raw signature (r || s) to ASN.1 DER
//     byte asnSig[72]; // Max ASN.1 length for P-256
//     word32 asnSigLen = sizeof(asnSig);

//     // Ensure proper ASN.1 encoding
//     ret = wc_ecc_rs_raw_to_sig(sigBuf, 32, sigBuf + 32, 32, asnSig, &asnSigLen);
//     if (ret != 0)
//     {
//         print_debug("Failed to convert raw signature to ASN.1 DER\n");
//         ret = -5;
//         goto exit;
//     }

//     // Debug: Print ASN.1 formatted signature
//     char hexStr[200];
//     char *ptr = hexStr;
//     ptr += sprintf(ptr, "ASN: ");
//     for (int i = 0; i < asnSigLen; i++)
//     {
//         ptr += sprintf(ptr, "%02X", asnSig[i]);
//     }
//     print_debug(hexStr);

//     // byte rawSig[64];
//     // word32 rawSigLen = sizeof(rawSig);

//     // ret = wc_ecc_sig_to_rs(asnSig, asnSigLen, rawSig, &rawSigLen);
//     // if (ret != 0)
//     // {
//     //     printf("Error converting ASN.1 signature: %d\n", ret);
//     //     return ret;
//     // }

//     // Verify the signature
//     // ret = wc_ecc_verify_hash_ex(asnSig, asnSigLen, hash, WC_SHA256_DIGEST_SIZE, &verify, &eccKey);
//     ret = wc_ecc_verify_hash_ex(asnS, sigLen, hash, sizeof(hash), &verify, &eccKey);
//     if (ret != 0 || verify != 1)
//     {
//         char sigStr[200];
//         sprintf(sigStr, "Signature verification failed: %d,%d,%d\n", verify, ret, asnSigLen);
//         print_debug(sigStr);
//         ret = -6;
//         goto exit;
//     }

//     print_debug("Signature verification successful!");
//     ret = 0; // Success

// exit:
//     wc_Sha256Free(&sha);
//     wc_ecc_free(&eccKey);
//     return ret;
// }

// int hash_firmware_verify(const byte *fwAddr, word32 fwLen, const byte *sigBuf, word32 sigLen) {
//      wc_Sha256 sha;
//     byte hash[WC_SHA256_DIGEST_SIZE];
//     int ret;
//     ecc_key eccKey;
//     word32 inOutIdx = 0;
//     const byte pubKey[] = {
//         0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
//         0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
//         0x42, 0x00, 0x04, 0x73, 0x04, 0xD8, 0x7F, 0xCC, 0x9A, 0x8C, 0xA4, 0x09,
//         0xF8, 0x52, 0xBC, 0x19, 0x1E, 0xD2, 0x2D, 0x11, 0x09, 0x03, 0x5F, 0xD4,
//         0xDC, 0xFB, 0x3F, 0xB6, 0xC2, 0x1A, 0xB1, 0x27, 0xEC, 0xA1, 0xFA, 0x57,
//         0x4D, 0x04, 0x81, 0x47, 0x75, 0x06, 0x2F, 0x66, 0x87, 0x14, 0x3F, 0x72,
//         0x32, 0x10, 0x9D, 0x70, 0x39, 0x4C, 0x7B, 0x76, 0x18, 0x23, 0x07, 0x8A,
//         0xA4, 0x5A, 0x1A, 0xC7, 0x32, 0xC2, 0x3C};
//     int verify;

//     // Initialize SHA-256
//     ret = wc_InitSha256(&sha);
//     if (ret != 0)
//     {
//         print_debug("Init sha failed\n");
//         return ret;
//     }

//     // Hash the firmware
//     ret = wc_Sha256Update(&sha, fwAddr, fwLen);
//     if (ret != 0)
//     {
//         print_debug("Update sha failed\n");
//         ret = -1;
//         goto exit;
//     }

//     ret = wc_Sha256Final(&sha, hash);
//     if (ret != 0)
//     {
//         print_debug("Final sha failed\n");
//         ret = -2;
//         goto exit;
//     }

//     // Import public key
//     ret = wc_ecc_import_x963(pubKey + 26, 65, &eccKey);
//     // ret = wc_ecc_import_x963(pubKey, sizeof(pubKey), &eccKey);
//     if (ret != 0)
//     {
//         print_debug("Public key import failed\n");
//         ret = -3;
//         goto exit;
//     }

//     // ------------------------------
//      // Export and print ECC public key
//     byte exportedPubKey[65];
//     word32 exportedLen = sizeof(exportedPubKey);

//     ret = wc_ecc_export_x963(&eccKey, exportedPubKey, &exportedLen);
//     if (ret != 0)
//     {
//         print_debug("Failed to export public key\n");
//         ret = -6;
//         goto exit;
//     }

//     // Print public key in hex
//     char pubKeyStr[200];
//     char *ptr1 = pubKeyStr;
//     ptr1 += sprintf(ptr1, "Public Key: ");
//     for (int i = 0; i < exportedLen; i++) {
//         ptr1 += sprintf(ptr1, "%02X", exportedPubKey[i]);
//     }
//     print_debug(pubKeyStr);
// // --------------------------------

//     // Set curve parameters
//     ret = wc_ecc_set_curve(&eccKey, 32, ECC_SECP256R1);
//     if (ret != 0)
//     {
//         print_debug("Set curve failed\n");
//         ret = -4;
//         goto exit;
//     }

//     byte asnSig[72]; // Max ASN.1 length for P-256
//     word32 asnSigLen = sizeof(asnSig);
//     char aaaa[32];
//     sprintf(aaaa, "len:%d",asnSigLen);
//     print_debug(aaaa);

//     byte r_fixed[33], s_fixed[33];
//     word32 rLen = 32, sLen = 32;
//     const byte *r = sigBuf;      // First 32 bytes = R
//     const byte *s = sigBuf + 32; // Next 32 bytes = S

//     // Handle ASN.1 encoding (prepend 0x00 if high bit is set)
//     if (r[0] & 0x80) {
//         r_fixed[0] = 0x00;
//         memcpy(r_fixed + 1, r, 32);
//         rLen = 33;
//     } else {
//         memcpy(r_fixed, r, 32);
//     }

//     if (s[0] & 0x80) {
//         s_fixed[0] = 0x00;
//         memcpy(s_fixed + 1, s, 32);
//         sLen = 33;
//     } else {
//         memcpy(s_fixed, s, 32);
//     }

//     ret = wc_ecc_rs_raw_to_sig(r_fixed, rLen, s_fixed, sLen, asnSig, &asnSigLen);
//     if (ret != 0)
//     {
//         char sigStr[200];
//         sprintf(sigStr, "Failed to convert raw signature to ASN.1 DER: %d", ret);
//         print_debug(sigStr);
//         ret = -4;
//         goto exit;
//     }
//     char hexStr[200];  // Buffer to hold hex string
//     char *ptr = hexStr;

//     ptr += sprintf(ptr, "ASN: ");
//     for (int i = 0; i < asnSigLen; i++) {
//         ptr += sprintf(ptr, "%02X", asnSig[i]);  // Convert each byte to hex
//     }

//     print_debug(hexStr);

//     // Verify using raw signature (r|s concatenated)
//     ret = wc_ecc_verify_hash_ex(asnSig, asnSigLen, hash, WC_SHA256_DIGEST_SIZE, &verify, &eccKey);
//     if (ret != 0 || verify != 1)
//     {
//         char sigStr[200]; // Buffer for formatted string
//         sprintf(sigStr, "Signature verification failed: %d,%d,%d,%d\n", verify, ret, asnSigLen, ASN_SIG_CONFIRM_E);
//         print_debug(sigStr);
//         // ret = -5;
//         goto exit;
//     }

//     ret = 0; // Success

// exit:
//     wc_Sha256Free(&sha);
//     wc_ecc_free(&eccKey);
//     return ret;
// }
void Initialize_ECC(ecc_key* eccKey)
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
                         const byte *sigBuf, word32 sigLen,ecc_key* eccKey)
{

    int ret;

    char sigHexaft[200]; // Needs to be 2*sigLen + 1 for hex representation
    char *ptra = sigHexaft;

    ptra += sprintf(ptra, "Raw Signature (%d bytes): ", sigLen);
    for (word32 i = 0; i < sigLen; i++)
    {
        ptra += sprintf(ptra, "%02X", sigBuf[i]);
    }
    print_debug(sigHexaft);
    char fwBuf[200]; // Needs to be 2*sigLen + 1 for hex representation
    char *ptrb = fwBuf;

    ptrb += sprintf(ptrb, "Raw Signature (%d bytes): ", fwLen);
    for (word32 i = 0; i < fwLen; i++)
    {
        ptrb += sprintf(ptrb, "%02X", fwAddr[i]);
    }
    print_debug(fwBuf);
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

    // Your ASN.1 DER public key

    // byte derSig[72]; // ECC DER signatures are typically <= 72 bytes
    // word32 derSigLen = sizeof(derSig);

    // ret = wc_ecc_rs_to_sig(
    //     sigBuf,      // R (first 32 bytes)
    //     sigBuf + 32, // S (next 32 bytes)
    //     derSig,      // Output DER buffer
    //     &derSigLen   // Output DER length
    // );

    // if (ret != 0)
    // {   char errStr[50];
    //     sprintf(errStr,"Failed to convert R||S to DER: %d(%s)\n", ret,wc_GetErrorString(ret));
    //     print_debug(errStr);
    //     wc_ecc_free(&eccKey);
    //     return ret;
    // }

    // Verify signature (assuming sigBuf is in DER format)
    ret = wc_SignatureVerify(
        WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
        fwAddr, fwLen,
        sigBuf, sigLen,
        eccKey, sizeof(eccKey));
    if (ret < 0)
    {
        char errStr[50];
        sprintf(errStr, "Signature verification failed %d\n", ret);
        print_debug(errStr);
    }
    else
    {
        print_debug("Signature verification successful\n");
    }

    wc_ecc_free(eccKey);
    return ret; // 0 = success, <0 = error
}

#endif
