#ifndef DECODER_SUPPORT_FUNC_H
#define DECODER_SUPPORT_FUNC_H

#include <wolfssl/wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfssl/wolfcrypt/integer.h>

#include "wolfssl/wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfssl/wolfcrypt/hash.h"
#include <wolfssl/wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfssl/wolfcrypt/asn_public.h>
#include "decoder_types.h"
#include <stddef.h>

/**********************************************************
******************* UTILITY FUNCTIONS ********************
**********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @param decoder_status The details of all subscribed channels
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
 */
int is_subscribed(const channel_id_t channel, const flash_entry_t *decoder_status);


/**********************************************************
 ************ CRYPTOGRAPHIC SUPPORT FUNCTIONS *************
 **********************************************************/

/**
 * @brief Decrypts a subscription update packet using RSA.
 *
 * @param pkt_len The length of the incoming update packet.
 * @param update_packet Pointer to the incoming packet that contains the encrypted data.
 * @param rsa_private_master_key Pointer to the RSA private master key used for decryption.
 * @param rsa_private_master_key_len The length (in bytes) of the RSA private master key.
 * @param decrypted_buffer Pointer to the buffer where the decrypted data will be stored.
 * @param decrypted_buffer_size The size (in bytes) of the decrypted buffer.
 *
 * @return 0 if decryption is successful. -1 if an error occurs during decryption.
 */
int decrypt_subscription_rsa(const pkt_len_t pkt_len,
                             const byte_t *update_packet,
                             const byte_t *rsa_private_master_key,
                             const size_t rsa_private_master_key_len,
                             byte_t *decrypted_buffer,
                             const size_t decrypted_buffer_size);


/**
 * @brief Decrypts a subscription update packet using AES.
 *
 * @param update_packet Pointer to the incoming packet that contains the encrypted data.
 * @param pkt_len The length of the incoming update packet.
 * @param aes_master_key Pointer to the AES master key used for decryption.
 * @param output_buf Pointer to the buffer where the decrypted data will be stored.
 *
 * @return 0 if decryption is successful. -1 if an error occurs during decryption.
 */
int decrypt_subscription_aes(const byte_t *update_packet,
                             const size_t pkt_len,
                             const byte_t *aes_master_key,
                             byte_t *output_buf);



/** @brief Derives a control word from a subscription key and initialization vector.
 *
 *  @param subscription_key A pointer to the subscription key used for deriving the control word.
 *  @param subscription_key_len The length of the subscription key.
 *  @param init_vector A pointer to the initialization vector used in the derivation process.
 *  @param derived_control_word A pointer to the buffer where the derived control word will be stored.
 *
 *  @return void. The derived control word is written directly to the provided buffer.
 */
int derive_control_word(const byte_t *subscription_key,
                        const byte_t *init_vector,
                        byte_t *derived_control_word);




/** @brief Initializes the Ed25519 key for frame signature verification.
 *
 *  @param ed25519_key_instance A pointer to the Ed25519 key instance that will be initialized.
 *  @param verification_key_der A pointer to the RAW verification key used for
 *                              initializing the Ed25519 key.
 *  @param ver_key_len The length of the RAW verification key in bytes.
 *  @return 0 if successful, -1 if error occurs
 */
int initialize_frame_verifier_eddsa(ed25519_key *ed25519_key_instance,
                                  const byte_t *verification_key_der,
                                  const unsigned int ver_key_len);





/** @brief Verifies the signature of a given frame using an Ed25519 key.
 *
 *  @param frame_data A pointer to the data of the frame whose signature is to be verified.
 *  @param frame_data_len The length of the frame data.
 *  @param signature_buf A pointer to the buffer containing the signature to be verified.
 *  @param signature_len The length of the signature.
 *  @param ecc_key_instance A pointer to the Ed25519 key used for verifying the signature. This key must be
 *                 properly initialized and correspond to the key used to generate the signature.
 *
 *  @return 0 if the signature is valid, a negative value if the signature is invalid or
 *          in case of an error during the verification process.
 */
int verify_frame_signature_eddsa(const byte_t *frame_data, const uint32_t frame_data_len,
                           const byte_t *signature_buf, const uint32_t signature_len,
                           const ed25519_key *ed25519_key_instance);





/**
 * @brief Decrypts an encrypted frame to produce the raw frame data.
 *
 * @param encr_frame_data A pointer to the encrypted frame data.
 * @param subscription_key A pointer to the subscription key used for decryption.
 * @param decr_frame_data A pointer to the buffer where the decrypted frame data will be stored.
 *
 * @return int Returns 0 on success or -1 otherwise.
 */
int decrypt_frame_data(const byte_t *encr_frame_data,
                       const byte_t *subscription_key,
                       byte_t *decr_frame_data);


#endif