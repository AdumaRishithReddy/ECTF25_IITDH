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
    uint8_t data[FRAME_SIZE];
    uint8_t sign[64];

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
    timestamp_t prev_timestamp;
    timestamp_t prev_der;
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

uint8_t curr_cw[KEY_LENGTH] = {0};

ecc_key eccKey;

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
    uint8_t key[16] = {0xA4, 0x4F, 0xFB, 0xDD,
                       0xC1, 0x8E, 0xA6, 0x9A,
                       0x39, 0xEB, 0x12, 0x0F,
                       0xB7, 0x7D, 0x5D, 0x2E};

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

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame)
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
    if (timestamp > decoder_status.subscribed_channels[channel].prev_timestamp)
    {
        decoder_status.subscribed_channels[channel].prev_timestamp = timestamp;
    }
    else
    {
        char err_out[64];
        sprintf(err_out, "Wrong timestamp/misordered: %llu,%llu\n", timestamp, decoder_status.subscribed_channels[channel].prev_timestamp);
        print_error(err_out);
        return -1;
    }

    print_debug("Checking subscription\n");

    if (is_subscribed(channel))
    {
        // channel--;
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
         *  Do any extra decoding here before returning the result to the host. */

        // -------------------------------------------------------------------------------------------------
        word32 derSigLen = 80;
        byte *derSig = (byte *)malloc(derSigLen);
        if (derSig == NULL)
        {
            print_error("Failed to allocate memory for derSig\n");
            return -1; // or appropriate error handling
        }

        int ver = wc_ecc_rs_raw_to_sig(
            signature, 32,
            signature + 32, 32,
            derSig,
            &derSigLen);

        if (ver != 0)
        {
            char errStr[50];
            sprintf(errStr, "Failed to convert R||S to DER: %d(%s)\n", ver, wc_GetErrorString(ver));
            print_debug(errStr);
            free(derSig); // Don't forget this!
            return -1;
        }

        // Print hex
        // char dersigHex[200];
        // char *ptr1 = dersigHex;

        // ptr1 += sprintf(ptr1, "DER Signature (%d bytes): ", derSigLen); // Use actual length
        // for (word32 i = 0; i < derSigLen; i++)
        // {
        //     ptr1 += sprintf(ptr1, "%02X", derSig[i]);
        // }
        // print_debug(dersigHex);

        // Use derSig...
        int ret = hash_firmware_verify(new_frame->data, frame_size, signature, sizeof(signature),&eccKey);
        if (ret < 0)
        {
            char err[64];
            sprintf(err, "Hash verification failed: %d, Frame: %d, DataLen: %d, SigLen: %d\n",
                    ret, frame_size, sizeof(new_frame->data), derSigLen);
            print_error(err);
        }

        free(derSig);
        // ----------------------------------------------------------------------------------------

        // int ret = hash_firmware_verify(new_frame->data, frame_size, signature, sizeof(signature));
        // if (ret < 0)
        // {
        //     char err[32];
        //     sprintf(err, "Hash verification failed: %d,%d,%d, SigLen: %d\n", ret, frame_size, sizeof(new_frame->data), sizeof(signature));
        //     print_error(err);
        // }
        char count[100];
        sprintf(count, "Frame Count: %d,%llu\n", frame_count, timestamp);
        print_debug(count);
        if (timestamp / 5000000 > decoder_status.subscribed_channels[channel].prev_der || curr_cw == NULL)
        {
            uint8_t sk[16];
            memcpy(sk, decoder_status.subscribed_channels[channel].sk, sizeof(decoder_status.subscribed_channels[channel].sk));
            uint8_t iv[16];
            memcpy(iv, decoder_status.subscribed_channels[channel].iv, sizeof(decoder_status.subscribed_channels[channel].iv));
            uint8_t time_salt[32];
            char ts_str[32];
            sprintf(ts_str, "%llu", (unsigned long long)(timestamp / 5000000));
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
            decoder_status.subscribed_channels[channel].prev_der = timestamp / 5000000;
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
        // print_hex_deb("Decrypted Frame", decrypted, frame_size);
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
            subscription[i].prev_timestamp = 0;
            subscription[i].prev_der = 0;

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

    Initialize_ECC(&eccKey);

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
    // timestamp_t prev_time[MAX_CHANNEL_COUNT] = {0};
    // timestamp_t prev_ts[MAX_CHANNEL_COUNT] = {0};
    init();
    print_debug("Decoder Booted!\n");
    while (1)
    {
        // print_debug("Ready\n");

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
            // crypto_example();09:31:49.502 09:31:55.063
#endif // CRYPTO_EXAMPLE
            list_channels();
            break;
        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            frame_count++;

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
