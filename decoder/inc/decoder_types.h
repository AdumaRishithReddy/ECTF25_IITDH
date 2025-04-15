#ifndef DECODER_TYPES_H
#define DECODER_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#include "wolfssl/wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfssl/wolfcrypt/hash.h"

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))


/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t
#define byte_t uint8_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 16
#define EMERGENCY_CHANNEL 0
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define DEFAULT_CHANNEL_ID 0xFFFFFFFF

// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

// Packet specific constants
#define MAX_DECR_FRAME_SIZE 64
#define FRAME_HASH_SIZE 32
#define MAX_FRAME_PKT_SIZE 109

// Subscription specific constants
#define MSTR_KEY_LENGTH 16
#define CHNL_KEY_LENGTH 16
#define INIT_VEC_LENGTH 16
#define SUBS_HASH_SIZE 32
#define MAX_SUBS_PKT_SIZE 96
#define SUBS_PAD_SIZE 8

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html


// Frame packet type (data is padded) - 109B
typedef struct
{
    channel_id_t channel;
    timestamp_t timestamp;
    byte_t pad_length;
    byte_t data[MAX_DECR_FRAME_SIZE];
    byte_t hash[FRAME_HASH_SIZE];
} frame_packet_t;


// Subscription update packet type (padded) - 96B
typedef struct
{
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
    byte_t channel_key[CHNL_KEY_LENGTH];
    byte_t init_vector[INIT_VEC_LENGTH];
    byte_t hash[SUBS_HASH_SIZE];
    byte_t aes_padding[SUBS_PAD_SIZE]; // Always ignore this field
} subscription_update_packet_t;


// Channel info (used in list response) - 20B
typedef struct
{
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;


// List response type
typedef struct
{
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

// Channel status type (used in decoder status)
typedef struct
{
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    byte_t channel_key[CHNL_KEY_LENGTH];
    byte_t init_vector[INIT_VEC_LENGTH];
    timestamp_t last_frame_timestamp;
    Aes frame_decryptor;
} channel_status_t;


// Flash entry type (used when reading and writing from flash)
typedef struct
{
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

#endif