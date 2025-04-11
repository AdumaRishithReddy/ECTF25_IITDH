#ifndef DECODER_CORE_FUNC_H
#define DECODER_CORE_FUNC_H

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
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
 */
int is_subscribed(const channel_id_t channel);

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
 */
int list_channels();

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
 */
int update_subscription(const pkt_len_t pkt_len, const byte_t *update);

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
 */
int decode(const pkt_len_t pkt_len, const frame_packet_t *new_frame);

/** @brief Initializes peripherals for system boot.
 */
void init();

/**********************************************************
 ************ CRYPTOGRAPHIC SUPPORT FUNCTIONS *************
 **********************************************************/

/** @brief Decrypts a subscription update packet using RSA.
 *
 *  @param pkt_len The length of the incoming update packet.
 *  @param update_packet A pointer to the incoming packet that contains the encrypted data.
 *  @param decrypted_buffer A pointer to the buffer where the decrypted data will be stored.
 *  @param decrypted_buffer_size The size of the decrypted buffer to ensure it can hold the decrypted data.
 *
 *  @return 0 if decryption is successful.
 *          -1 if an error occurs during decryption (e.g., invalid packet length, decryption failure).
 */
int decrypt_subscription_rsa(const pkt_len_t pkt_len,
                             const byte_t *update_packet,
                             byte_t *decrypted_buffer,
                             const size_t decrypted_buffer_size);



/** @brief Decrypts a subscription update packet using AES.
 *
 *  @param update_packet A pointer to the incoming packet that contains the encrypted data.
 *  @param pkt_len The length of the incoming update packet.
 *  @param output_buf A pointer to the buffer where the decrypted data will be stored.
 *
 *  @return 0 if decryption is successful.
 *          -1 if an error occurs during decryption (e.g., invalid packet length, decryption failure).
 */
int decrypt_subscription_aes(const byte_t *update_packet,
                             const size_t pkt_len,
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