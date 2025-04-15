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
 *  @return 1 if the decoder is subscribed to the channel.  0 if not.
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



/**
 * @brief Decrypts an encrypted frame to produce the raw frame data.
 *
 * @param frame_decryptor A pointer to the Aes structure used for decryption.
 * @param encr_frame_data A pointer to the encrypted frame data.
 * @param decr_frame_data A pointer to the buffer where the decrypted frame data will be stored.
 * @param data_len Length of data to be decrypted
 *
 * @return int Returns 0 on success or -1 otherwise.
 */
int decrypt_frame_data(Aes * frame_decryptor,
                        const byte_t *encr_frame_data, 
                        byte_t *decr_frame_data,
                        const size_t data_len);


void enable_mpu_access_rw(unsigned int region_num,
                        unsigned int base_register,
                        unsigned int region_size);

void enable_mpu_access_ro(unsigned int region_num,
                        unsigned int base_register,
                        unsigned int region_size);

void disable_mpu_access(unsigned int region_num,
                        unsigned int base_register,
                        unsigned int region_size);
#endif