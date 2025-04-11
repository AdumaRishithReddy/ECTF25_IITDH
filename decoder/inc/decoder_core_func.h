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
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
 */
int update_subscription(const pkt_len_t pkt_len, const byte_t *update);


/** @brief Processes a packet containing frame data of emergency channel.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful. Negative if error.
 */
int decode_emergency_channel(const pkt_len_t pkt_len, const frame_packet_t *new_frame);


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