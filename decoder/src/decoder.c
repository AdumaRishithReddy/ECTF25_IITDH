/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
// #include <mxc_delay.h>
// #define _POSIX_C_SOURCE 199309L
// #include <sys/time.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "cJSON.h"
// #include <unistd.h>
#include "simple_uart.h"
#include "mxc_sys.h"
#include "nvic_table.h"
#include "core_cm4.h"

#include "mxc.h"
#include "board.h"

#define TIMER MXC_TMR0

// #define KEY_STORAGE_ADDR 0x20001000 // Example protected SRAM address
// #define KEY_STORAGE_SIZE 64
#define MPU_REGION_NUMBER 0         // Select an MPU region
#define KEY_STORAGE_ADDR 0x2001FF00 // 32 bytes for key

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is intended
 *  to be an example of how you *may* use cryptography in your design. You
 *  are not limited nor required to use this interface in your design. It is
 *  recommended for newer teams to start by only using the simple crypto
 *  library until they have a working design. */
#include "simple_crypto.h"
#endif // CRYPTO_EXAMPLE

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 80
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

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
    // uint8_t type;
    uint8_t sign[64];
    uint8_t data[FRAME_SIZE];

} frame_packet_t;

typedef struct
{
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
    uint8_t sk[16];
    uint8_t iv[16];
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
volatile int frame_count = 0;
volatile int timer_expired = 0;
typedef struct
{
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    uint8_t sk[16];
    uint8_t iv[16];
} channel_status_t;

typedef struct
{
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
volatile flash_entry_t decoder_status;
int idx = 0;
timestamp_t prev_ts = 0;
uint8_t curr_cw[KEY_LENGTH] = {0};

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
 */
int is_subscribed(channel_id_t channel)
{
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL)
    {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active)
        {
            return 1;
        }
    }
    return 0;
}
// void handle_interrupt(int sig)
// {
//     print_debug("[INFO] Interrupt received! Stopping...");
//     stop = 1;
// }
/** @brief Prints the boot reference design flag
 *
 *  TODO: Remove this in your final design
 */
// void boot_flag(void)
// {
//     char flag[28];
//     char output_buf[128] = {0};

//     for (int i = 0; aseiFuengleR[i]; i++)
//     {
//         flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
//         flag[i + 1] = 0;
//     }
//     sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
//     print_debug(output_buf);
// }

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/
void print_hex_deb(const char *label, uint8_t *data, size_t len)
{
    char buffer[KEY_LENGTH * 2 + 50]; // Buffer to store formatted output
    char *ptr = buffer;

    ptr += sprintf(ptr, "%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        ptr += sprintf(ptr, "%02X", data[i]);
    }

    print_debug(buffer); // Print the formatted hex output
}
/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
 */
int list_channels()
{
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].active)
        {
            resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}
void hex_to_byte_array(const char *hex_str, uint8_t *byte_array, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
}

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
// #define USERSA
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update)
{
    // flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    int i;
    // uint8_t key[16];
    // load_master_key_from_json( DECODER_ID, key);
    uint8_t *decrypted = (uint8_t *)malloc(pkt_len);
    if (!decrypted)
    {
        print_error("Memory allocation failed\n");
        return -1;
    }
// wolfSSL_Debugging_ON();
// wolfCrypt_Init();

// print_hex_deb("DER", der, derSz);
#ifdef USERSA
    // wolfCrypt_Init();
    uint8_t rsa_private_key[1191] = {
        0x30, 0x82, 0x04, 0xA3, 0x02, 0x01, 0x00, 0x02,
        0x82, 0x01, 0x01, 0x00, 0xAD, 0x1A, 0x13, 0x64,
        0x42, 0x3D, 0xCC, 0xFE, 0xD7, 0xEC, 0x6C, 0x8A,
        0x1C, 0x9C, 0x33, 0xB3, 0x0C, 0x29, 0x3C, 0x3F,
        0x71, 0x3B, 0xFF, 0x5D, 0x2A, 0x2F, 0xB8, 0x8C,
        0x59, 0x73, 0x8B, 0xC7, 0xF8, 0xFB, 0xD6, 0xE9,
        0x6B, 0x80, 0x76, 0x25, 0x2A, 0x37, 0x5E, 0x4A,
        0x8A, 0x05, 0xFD, 0x33, 0x44, 0x8D, 0x20, 0x63,
        0xF6, 0x69, 0xA7, 0xD3, 0xE0, 0x88, 0xD1, 0x47,
        0x17, 0x35, 0x1F, 0x86, 0xFB, 0xDF, 0x2C, 0x04,
        0xEC, 0x28, 0x36, 0xA9, 0xB1, 0x37, 0xD1, 0xB4,
        0x2D, 0x50, 0xB8, 0x8B, 0xF4, 0xB2, 0xF4, 0xF9,
        0x8A, 0xE3, 0x1E, 0xA9, 0x4C, 0x7B, 0x65, 0x65,
        0x1F, 0xBE, 0xB8, 0xAB, 0x9E, 0xA7, 0x0D, 0xF7,
        0xD0, 0xD9, 0xA7, 0xE6, 0x3E, 0x1C, 0x76, 0x7A,
        0xE8, 0x45, 0xEB, 0x1C, 0xA4, 0x92, 0x21, 0x77,
        0xFB, 0x5B, 0x53, 0x63, 0x1E, 0x9A, 0x2E, 0xBF,
        0xF1, 0x47, 0x22, 0xE0, 0xC7, 0x39, 0x15, 0xEF,
        0xBD, 0xAF, 0x3B, 0x34, 0xF7, 0xB1, 0x0C, 0x0E,
        0x9C, 0x86, 0x53, 0x44, 0x7C, 0xDA, 0xFF, 0x18,
        0x34, 0xCA, 0x9C, 0x16, 0xBB, 0xF4, 0x5A, 0x80,
        0xFE, 0x53, 0x67, 0x26, 0x1B, 0xC9, 0x7E, 0x10,
        0x67, 0xDA, 0xCC, 0x70, 0x1F, 0xB9, 0x5B, 0x5D,
        0x71, 0xD3, 0x09, 0x05, 0x40, 0xD2, 0x0C, 0x9D,
        0xB1, 0x5B, 0xCC, 0x31, 0xAE, 0x25, 0x5F, 0xE6,
        0xBD, 0x68, 0x7E, 0x35, 0xBB, 0x4A, 0x88, 0xA9,
        0xAA, 0xD9, 0x62, 0x40, 0xFE, 0xB1, 0x3B, 0x3B,
        0x25, 0x7A, 0x0F, 0xAE, 0xD7, 0x07, 0x1C, 0x8E,
        0x08, 0x94, 0x83, 0x97, 0x9B, 0xE1, 0x21, 0x47,
        0x43, 0x40, 0x1B, 0x8D, 0x0D, 0x14, 0x68, 0x69,
        0x04, 0x24, 0xEE, 0x27, 0xCC, 0x6E, 0x77, 0xFF,
        0x1A, 0x85, 0x51, 0xAF, 0x82, 0xC0, 0xAE, 0x44,
        0xBA, 0xDD, 0xF3, 0x53, 0x56, 0xCF, 0xDC, 0x3A,
        0x42, 0x34, 0xF3, 0xD3, 0x02, 0x03, 0x01, 0x00,
        0x01, 0x02, 0x82, 0x01, 0x00, 0x0E, 0x28, 0x43,
        0xCD, 0xBF, 0x5D, 0x2E, 0x96, 0xE9, 0x31, 0xFC,
        0xEE, 0x8E, 0xC8, 0x77, 0xB1, 0xFD, 0x1C, 0xA2,
        0x40, 0xCE, 0x12, 0x0A, 0x20, 0xA4, 0x82, 0xA2,
        0xA5, 0x57, 0xEB, 0x8B, 0x53, 0x1F, 0x99, 0xF9,
        0x49, 0xBD, 0xF1, 0x13, 0xB8, 0x96, 0x6B, 0x50,
        0xDA, 0xE7, 0xCE, 0xF5, 0x96, 0x6B, 0xD4, 0xDF,
        0x01, 0x4D, 0xF5, 0xF6, 0x33, 0xED, 0xF9, 0x42,
        0xA4, 0x7D, 0xD1, 0x6A, 0x72, 0xAF, 0xC6, 0xE0,
        0xE2, 0xC6, 0x2D, 0xC3, 0xCA, 0xBD, 0x23, 0xC3,
        0x92, 0xE8, 0xE1, 0xE1, 0x36, 0x11, 0x1D, 0x51,
        0xCB, 0xD7, 0x00, 0x1C, 0x51, 0xDC, 0x5F, 0x7B,
        0x3B, 0x7A, 0x0D, 0x2F, 0x2D, 0x5A, 0x1C, 0x6F,
        0x98, 0x05, 0x0C, 0xC8, 0x1E, 0x9C, 0x95, 0xD7,
        0x5A, 0xD6, 0x04, 0x61, 0xE6, 0x45, 0xCF, 0x6D,
        0xCD, 0x52, 0x51, 0x75, 0xD0, 0x75, 0x80, 0x46,
        0xB2, 0x8C, 0x19, 0x35, 0x50, 0xEA, 0x72, 0xED,
        0x72, 0x98, 0x2B, 0xE5, 0xA0, 0x2B, 0x8C, 0xDC,
        0x13, 0xB4, 0x80, 0xFC, 0xF0, 0x73, 0x37, 0xC5,
        0x3C, 0x90, 0xB5, 0x74, 0x64, 0x4E, 0xC9, 0xB8,
        0x2A, 0xD4, 0xB5, 0x46, 0x99, 0x60, 0x9B, 0x8C,
        0xC9, 0x03, 0xE4, 0x51, 0x61, 0xE2, 0x8A, 0x04,
        0x06, 0xDB, 0x96, 0x4E, 0xB3, 0x96, 0x9C, 0x0B,
        0x14, 0x69, 0x38, 0x6D, 0x09, 0x92, 0x7F, 0xB7,
        0x0D, 0x3D, 0x46, 0x20, 0x0A, 0x1F, 0x1E, 0x72,
        0x68, 0xD8, 0x3A, 0x86, 0x7D, 0x93, 0xC9, 0x73,
        0xAE, 0xC4, 0x61, 0x8E, 0x63, 0x73, 0xA8, 0x83,
        0x8D, 0x07, 0x00, 0x4B, 0x8E, 0xF4, 0x57, 0x43,
        0x47, 0xF3, 0x8E, 0x3D, 0xC8, 0x8B, 0x4A, 0x08,
        0x05, 0x5C, 0x21, 0x57, 0x91, 0xE1, 0x1E, 0x8B,
        0x4B, 0x76, 0x06, 0x20, 0x55, 0x36, 0xA4, 0x15,
        0x87, 0xE3, 0x62, 0xB3, 0x66, 0x02, 0x32, 0x1E,
        0xE4, 0x7F, 0x13, 0x43, 0x01, 0x02, 0x81, 0x81,
        0x00, 0xC3, 0x71, 0x28, 0xF0, 0xFA, 0x44, 0x2D,
        0xB1, 0xC4, 0x54, 0xC2, 0x38, 0xA0, 0x23, 0xCF,
        0xE6, 0x34, 0x42, 0x2A, 0xFE, 0xC4, 0x6D, 0xE6,
        0xE3, 0x8D, 0x4A, 0xC4, 0x07, 0xA8, 0xC9, 0x1E,
        0x96, 0xA9, 0x1E, 0x99, 0x72, 0x7B, 0x51, 0x47,
        0x29, 0x96, 0x98, 0xA6, 0xC3, 0x2A, 0xEC, 0x1B,
        0x14, 0x8A, 0xE6, 0x7F, 0xED, 0xDC, 0x00, 0x39,
        0xDB, 0xF2, 0xE9, 0x63, 0xE7, 0xAB, 0xDF, 0x2C,
        0xF3, 0x3F, 0x00, 0x08, 0xCD, 0x88, 0x0D, 0x69,
        0x01, 0xB3, 0x6B, 0x58, 0x0C, 0xF3, 0x65, 0x0D,
        0xFF, 0xD7, 0x03, 0xB6, 0x25, 0xD7, 0x4C, 0xC3,
        0xF1, 0x56, 0x70, 0xB1, 0xF3, 0xFE, 0x88, 0x53,
        0x52, 0xB3, 0x8A, 0xA0, 0x00, 0xDF, 0x58, 0x87,
        0x41, 0x85, 0xDC, 0x1C, 0x78, 0xCF, 0xA3, 0x63,
        0x70, 0xAF, 0xB5, 0x3D, 0x0C, 0x84, 0xBE, 0x7D,
        0x79, 0x56, 0x30, 0x64, 0xB3, 0xBF, 0xAC, 0xE8,
        0x7B, 0x02, 0x81, 0x81, 0x00, 0xE2, 0xBC, 0xD9,
        0xA0, 0x80, 0x3E, 0x12, 0x49, 0x11, 0x1D, 0x42,
        0xEE, 0x69, 0x70, 0x33, 0x0F, 0x90, 0xCD, 0x27,
        0x30, 0x14, 0x90, 0x6D, 0xAA, 0x3E, 0x0A, 0x4E,
        0x6C, 0x7E, 0x09, 0x5C, 0x7E, 0x4A, 0xB1, 0xE5,
        0x29, 0xBC, 0x85, 0x72, 0xA3, 0x94, 0x05, 0xA5,
        0x46, 0xFF, 0xF8, 0x03, 0xA0, 0xFB, 0x7A, 0x5E,
        0xD0, 0x7C, 0xDD, 0x2E, 0xE5, 0x6B, 0x50, 0xEC,
        0xDB, 0xB5, 0xAC, 0x99, 0x14, 0xAC, 0xCA, 0x0B,
        0x5B, 0x3E, 0xE9, 0x12, 0xD7, 0xA3, 0x95, 0x01,
        0x5A, 0xE5, 0xA6, 0x11, 0x7D, 0xFE, 0xAD, 0x77,
        0xB7, 0xED, 0x65, 0x6D, 0xEB, 0x0D, 0x5B, 0x70,
        0x20, 0x81, 0x8E, 0x73, 0xD8, 0x19, 0xFD, 0x04,
        0x0A, 0xB7, 0x33, 0x63, 0xB0, 0x5E, 0x3D, 0xB4,
        0x74, 0xA7, 0x45, 0xBC, 0x08, 0x3C, 0x0E, 0xAE,
        0x8B, 0xD8, 0x63, 0x25, 0xF6, 0x02, 0x86, 0xF6,
        0x10, 0x28, 0xC0, 0x7E, 0x89, 0x02, 0x81, 0x81,
        0x00, 0x81, 0x4A, 0xAB, 0xF5, 0xF6, 0xEA, 0x01,
        0x7C, 0x97, 0x50, 0x27, 0x08, 0x44, 0xD0, 0x4C,
        0x29, 0x93, 0x2A, 0xAE, 0xBC, 0xC9, 0x7F, 0x96,
        0xFD, 0xB4, 0x2B, 0xE0, 0xD0, 0xDC, 0x54, 0xE8,
        0x5A, 0x6C, 0xD8, 0xE4, 0x54, 0x3A, 0xC6, 0x43,
        0x18, 0x7D, 0x1A, 0xD1, 0x3F, 0x4D, 0x76, 0xD2,
        0x57, 0x5D, 0xA8, 0x2C, 0xBB, 0x53, 0x0E, 0x07,
        0x38, 0xBD, 0x52, 0xAE, 0x97, 0xC5, 0x38, 0xA7,
        0xC8, 0xE7, 0x45, 0x83, 0x8D, 0x4C, 0x52, 0xEA,
        0xC3, 0x88, 0x49, 0x1B, 0xFF, 0xBD, 0x48, 0x7D,
        0xE1, 0x61, 0x01, 0x80, 0x8F, 0x3A, 0x05, 0xFB,
        0x9D, 0xFD, 0x3C, 0x22, 0x4D, 0x32, 0x76, 0x47,
        0x00, 0xEF, 0xEB, 0x65, 0xFC, 0x0D, 0xC4, 0xC7,
        0xFD, 0x8D, 0xAB, 0x56, 0x5E, 0x89, 0xA6, 0x22,
        0x13, 0x9A, 0xF9, 0x7F, 0xC0, 0x77, 0x54, 0x79,
        0x37, 0x3A, 0xD0, 0x5A, 0xDE, 0x1A, 0x90, 0x2D,
        0x5F, 0x02, 0x81, 0x80, 0x4B, 0x55, 0xB1, 0xFD,
        0x58, 0xFE, 0xC6, 0xB6, 0x8E, 0x40, 0x29, 0xAF,
        0xEB, 0x4A, 0x83, 0x3C, 0xA5, 0xC0, 0xF4, 0x47,
        0x4E, 0x5D, 0xDA, 0x82, 0x19, 0x10, 0xF5, 0x93,
        0xA8, 0xA0, 0xD5, 0xA1, 0x84, 0x91, 0xEC, 0xF1,
        0x5C, 0x18, 0xFE, 0xC9, 0x08, 0xF2, 0x83, 0x42,
        0xBE, 0xE3, 0x99, 0xD9, 0x10, 0x15, 0x4D, 0x91,
        0x7A, 0x1B, 0x47, 0x6C, 0xA4, 0xA6, 0x83, 0xBC,
        0x50, 0x75, 0xA3, 0x7B, 0x32, 0x1A, 0x03, 0x81,
        0xF2, 0xBA, 0x20, 0x2F, 0x93, 0xC3, 0x7B, 0x6A,
        0xC7, 0x28, 0xD1, 0x61, 0x0A, 0x90, 0x7A, 0x59,
        0x9B, 0x3F, 0xFB, 0x30, 0x81, 0x04, 0xA3, 0x91,
        0xB9, 0x5A, 0x2A, 0x75, 0x5F, 0xD5, 0x28, 0x55,
        0xA3, 0x1F, 0x28, 0xFD, 0x3D, 0xA2, 0xC4, 0xE5,
        0x89, 0x7A, 0x6B, 0x0A, 0x55, 0x62, 0x0F, 0x6E,
        0x99, 0x9B, 0xFF, 0xCD, 0xE8, 0x73, 0x0D, 0x28,
        0xBB, 0x51, 0x91, 0xF9, 0x02, 0x81, 0x80, 0x4F,
        0xEC, 0x49, 0x6A, 0x81, 0xA1, 0x30, 0xFA, 0x2A,
        0xCD, 0xCC, 0xED, 0xCC, 0x1D, 0x35, 0x12, 0x77,
        0x3A, 0xB5, 0x62, 0x45, 0xFD, 0x4C, 0x97, 0x80,
        0x7E, 0xAE, 0xB9, 0x5E, 0x44, 0xE1, 0x69, 0xED,
        0xBC, 0x7C, 0x2E, 0x9F, 0xFE, 0xE2, 0xF1, 0x77,
        0xE3, 0x0B, 0x31, 0xF7, 0x75, 0x74, 0x00, 0xDA,
        0x2A, 0x64, 0x20, 0x58, 0x8E, 0x29, 0xEE, 0x66,
        0x70, 0xAB, 0x78, 0x6C, 0xD2, 0xF8, 0xDB, 0x44,
        0x27, 0x42, 0xFE, 0xCB, 0x7E, 0x0F, 0x4A, 0x8F,
        0x3E, 0x6F, 0x85, 0xF7, 0x04, 0xC6, 0xB4, 0xFC,
        0x1E, 0x8C, 0x35, 0x11, 0x6E, 0xB4, 0xCF, 0xF1,
        0x5D, 0x6C, 0x9A, 0x14, 0xC7, 0xFD, 0x22, 0x1C,
        0xD8, 0x0F, 0x5D, 0xAE, 0x79, 0x56, 0x76, 0xFC,
        0x2F, 0xFA, 0x8E, 0xF2, 0xB9, 0xE2, 0x55, 0x23,
        0x92, 0xD2, 0x5A, 0x81, 0xB1, 0xDD, 0x27, 0x30,
        0x1C, 0x70, 0xED, 0xED, 0x95, 0x37, 0x4D};
    int ret = decrypt_rsa(rsa_private_key, sizeof(rsa_private_key), update, pkt_len, decrypted, pkt_len);
    print_debug("afag");

    if (ret != 0)
    {
        char buffer[64];
        sprintf(buffer, "RSA Decryption failed! Error code: %d\n", ret);
        print_error(buffer);
        free(decrypted);
        return -1;
    }
    // }wolfCrypt_Cleanup();
// pkt_len = decrypted_len;
#else
    uint8_t key[16] = {0x94, 0x19, 0xB8, 0x84, 0x42, 0x85, 0x68, 0xF5,
                       0x12, 0x7C, 0xEB, 0xB9, 0x2E, 0x6B, 0xB2, 0x44};

    char key_str[KEY_SIZE * 2 + 1]; // 2 chars per byte + 1 for null terminator
    for (int i = 0; i < KEY_SIZE; i++)
    {
        sprintf(&key_str[i * 2], "%02X", key[i]); // Convert byte to hex string
    }
    key_str[KEY_SIZE * 2] = '\0'; // Null-terminate string

    // Allocate memory for decrypted buffer

    // Decrypt the frame
    if (decrypt_sym(update, pkt_len, key, decrypted) != 0)
    {
        print_error("Decryption failed\n");
        free(decrypted);
        return -1;
    }
#endif

    // Remove PKCS#7 padding
    uint8_t pad_length = decrypted[pkt_len - 1];

    if (pad_length == 0 || pad_length > BLOCK_SIZE || pad_length > pkt_len)
    {
        print_error("Invalid padding length!\n");
        free(decrypted);
        return -1;
    }

    // Ensure all padding bytes are correct
    for (size_t j = pkt_len - pad_length; j < pkt_len; j++)
    {
        if (decrypted[j] != pad_length)
        {
            print_error("Corrupted padding detected!\n");
            free(decrypted);
            return -1;
        }
    }

    // Correct way to use decrypted data
    subscription_update_packet_t *update_dec = (subscription_update_packet_t *)decrypted;

    if (update_dec->channel == EMERGENCY_CHANNEL)
    {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].id == update_dec->channel)
        {

            decoder_status.subscribed_channels[i].active = true;

            decoder_status.subscribed_channels[i].start_timestamp = update_dec->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update_dec->end_timestamp;

            memcpy(decoder_status.subscribed_channels[i].sk, update_dec->sk, sizeof(update_dec->sk));
            memcpy(decoder_status.subscribed_channels[i].iv, update_dec->iv, sizeof(update_dec->iv));

            print_hex_deb("Stored IV", decoder_status.subscribed_channels[i].iv, 16);
            print_hex_deb("Stored SK", decoder_status.subscribed_channels[i].sk, 16);

            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT)
    {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
 */

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame, timestamp_t *prev_time)
{
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;
    timestamp_t timestamp;
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + sizeof(new_frame->sign));
    channel = new_frame->channel;
    // channel=(channel >> 8) | (channel << 8);
    timestamp = new_frame->timestamp;
    uint8_t signature[64];
    memcpy(signature, new_frame->sign, sizeof(new_frame->sign));
    if (timestamp > *prev_time)
    {
        *prev_time = timestamp;
    }
    else
    {
        print_error("Wrong timestamp/misordered");
        return -1;
    }

    print_debug("Checking subscription\n");

    if (is_subscribed(channel))
    {
        // channel--;
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
         *  Do any extra decoding here before returning the result to the host. */
        int ret = hash_firmware_verify(new_frame->data, frame_size, signature, sizeof(signature));
        if (ret < 0)
        {
            char err[32];
            sprintf(err, "Hash verification failed: %d,%d,%d, SigLen: %d\n", ret, frame_size, sizeof(new_frame->data), sizeof(signature));
            print_error(err);
        }

        if (timestamp / 10000 > prev_ts || curr_cw == NULL)
        {
            uint8_t sk[16];
            memcpy(sk, decoder_status.subscribed_channels[channel].sk, sizeof(decoder_status.subscribed_channels[channel].sk));
            uint8_t iv[16];
            memcpy(iv, decoder_status.subscribed_channels[channel].iv, sizeof(decoder_status.subscribed_channels[channel].iv));
            uint8_t time_salt[32];
            char ts_str[32];
            sprintf(ts_str, "%llu", (unsigned long long)(timestamp / 10000));
            hash(ts_str, strlen(ts_str), time_salt);
            uint8_t mixed_iv[16];
            for (int i = 0; i < 16; i++)
            {
                mixed_iv[i] = iv[i] ^ time_salt[i];
            }

            uint8_t derived_key[16];
            derive_key(sk, 16, mixed_iv, derived_key);
            memcpy(curr_cw, derived_key, 16);
            print_hex_deb("Global Derived Key", curr_cw, KEY_LENGTH);
            *prev_time = timestamp / 10000;
        }
        idx++;
        uint8_t key[16];
        memcpy(key, curr_cw, sizeof(curr_cw));

        uint8_t decrypted[frame_size];

        // Decrypt the frame
        if (decrypt_sym(new_frame->data, frame_size, key, decrypted) != 0)
        {
            print_error("Decryption failed\n");
            return -1;
        }

        // Remove PKCS#7 padding
        uint8_t pad_length = decrypted[frame_size - 1];

        // Validate padding range
        if (pad_length == 0 || pad_length > BLOCK_SIZE)
        {
            print_error("Invalid padding length!\n");
            return -1;
        }
        // Ensure all padding bytes are correct
        for (size_t i = frame_size - pad_length; i < frame_size; i++)
        {
            if (decrypted[i] != pad_length)
            {
                print_error("Corrupted padding detected!\n");
                return -1;
            }
        }

        // Compute unpadded length
        uint16_t unpadded_len = frame_size - pad_length;

        // Send the correctly decrypted and unpadded frame
        write_packet(DECODE_MSG, decrypted, unpadded_len);
        return 0;
    }
    else
    {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
 */
void init()
{
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT)
    {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
         *  This data will be persistent across reboots of the decoder. Whenever the decoder
         *  processes a subscription update, this data will be updated.
         */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++)
        {

            subscription[i].id = i;
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;

            uint8_t default_sk[16] = {0xD7, 0x67, 0xCB, 0x38, 0x4C, 0xFD, 0x40, 0x57,
                                      0x11, 0xB1, 0xCA, 0x80, 0x47, 0x09, 0x6B, 0x5F};

            uint8_t default_iv[16] = {0xD7, 0x67, 0xCB, 0x38, 0x4C, 0xFD, 0x40, 0x57,
                                      0x11, 0xB1, 0xCA, 0x80, 0x47, 0x09, 0x6B, 0x5F};

            memcpy(decoder_status.subscribed_channels[i].sk, default_sk, 16);
            memcpy(decoder_status.subscribed_channels[i].iv, default_iv, 16);
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0)
    {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1)
            ;
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void)
{
    wolfSSL_Debugging_ON();
    wolfCrypt_Init();
    char output_buf[128] = {0};
    uint8_t uart_buf[258];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;
    timestamp_t prev_time = 0;
    init();
    print_debug("Decoder Booted!\n");
    while (1)
    {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0)
        {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd)
        {
        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
#ifdef CRYPTO_EXAMPLE
            // Run the crypto example
            // TODO: Remove this from your design
            // crypto_example();
#endif // CRYPTO_EXAMPLE
            list_channels();
            break;
        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf, &prev_time);
            break;
        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;
        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
