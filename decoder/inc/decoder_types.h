#ifndef DECODER_TYPES_H
#define DECODER_TYPES_H

#include <stdint.h>
#include <stdbool.h>

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

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define SIGNATURE_SIZE 64
#define FRAME_SIZE 80
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define DEFAULT_CHANNEL_ID 0xFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

#define SUBS_KEY_LENGTH 16
#define INIT_VEC_LENGTH 16
#define CTRL_WRD_LENGTH 16
#define PBKDF2_ITERATIONS 1000 // Number of PBKDF2 iterations
#define PBKDF2_SALT_LENGTH 16
#define CTRL_WRD_INTERVAL 10000000
// This is a canary value so we can confirm whether this decoder has booted before

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
typedef struct
{
    channel_id_t channel;
    timestamp_t timestamp;
    byte_t sign[SIGNATURE_SIZE];
    byte_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct
{
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
    byte_t subscription_key[SUBS_KEY_LENGTH];
    byte_t init_vector[INIT_VEC_LENGTH];
} subscription_update_packet_t;

typedef struct
{
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct
{
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/
typedef struct
{
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    byte_t subscription_key[SUBS_KEY_LENGTH];
    byte_t init_vector[INIT_VEC_LENGTH];
    byte_t control_word[CTRL_WRD_LENGTH];
    timestamp_t last_ctrl_wrd_gen_time;
} channel_status_t;

typedef struct
{
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;
#endif