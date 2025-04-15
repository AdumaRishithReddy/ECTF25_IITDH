#ifndef DECODER_CORE_FUNC_H
#define DECODER_CORE_FUNC_H

#include "decoder_types.h"

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
 *  @param encr_update_pkt A pointer to a channel subscription update packet
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
 */
int update_subscription(const pkt_len_t pkt_len, const subscription_update_packet_t *encr_update_pkt);


/** @brief Erases a subscription at index I in the decoder status struct.
 *
 *  @param channel_id The channel id whose data to erase
 *
 *  @note This function MUST NOT be called on a subscription expiry.
 *        It is only used when a subscription update/init fails.
 */
int erase_subscription(channel_id_t channel_id);


/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful. Negative if error.
 */
int decode(const pkt_len_t pkt_len, const frame_packet_t *new_frame);


/** @brief Initializes peripherals for system boot.
 */
void init();

#endif