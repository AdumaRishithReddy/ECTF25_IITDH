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
// #define _POSIX_C_SOURCE 199309L
#include <sys/time.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
// #include <cjson/cJSON.h>

#include "simple_uart.h"

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
#define FRAME_SIZE 64
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

typedef struct
{
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
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
flash_entry_t decoder_status;

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// TODO: remove this from your final design
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;
const aErjfkdfru aseiFuengleR[] = {0x1ffe4b6, 0x3098ac, 0x2f56101, 0x11a38bb, 0x485124, 0x11644a7, 0x3c74e8, 0x3c74e8, 0x2f56101, 0x2ca498, 0x127bc, 0x2e590b1, 0x1d467da, 0x1fbf0a2, 0x11a38bb, 0x2b22bad, 0x2e590b1, 0x1ffe4b6, 0x2b61fc1, 0x1fbf0a2, 0x1fbf0a2, 0x2e590b1, 0x11644a7, 0x2e590b1, 0x1cc7fb2, 0x1d073c6, 0x2179d2e, 0};
const aErjfkdfru djFIehjkklIH[] = {0x138e798, 0x2cdbb14, 0x1f9f376, 0x23bcfda, 0x1d90544, 0x1cad2d2, 0x860e2c, 0x860e2c, 0x1f9f376, 0x25cbe0c, 0x11c82b4, 0x35ff56, 0x3935040, 0xc7ea90, 0x23bcfda, 0x1ae6dee, 0x35ff56, 0x138e798, 0x21f6af6, 0xc7ea90, 0xc7ea90, 0x35ff56, 0x1cad2d2, 0x35ff56, 0x2b15630, 0x3225338, 0x4431c8, 0};
typedef int skerufjp;
skerufjp siNfidpL(skerufjp verLKUDSfj)
{
    aErjfkdfru ubkerpYBd = 12 + 1;
    skerufjp xUrenrkldxpxx = 2253667944 % 0x432a1f32;
    aErjfkdfru UfejrlcpD = 1361423303;
    verLKUDSfj = (verLKUDSfj + 0x12345678) % 60466176;
    while (xUrenrkldxpxx-- != 0)
    {
        verLKUDSfj = (ubkerpYBd * verLKUDSfj + UfejrlcpD) % 0x39aa400;
    }
    return verLKUDSfj;
}
typedef uint8_t kkjerfI;
kkjerfI deobfuscate(aErjfkdfru veruioPjfke, aErjfkdfru veruioPjfwe)
{
    skerufjp fjekovERf = 2253667944 % 0x432a1f32;
    aErjfkdfru veruicPjfwe, verulcPjfwe;
    while (fjekovERf-- != 0)
    {
        veruioPjfwe = (veruioPjfwe - siNfidpL(veruioPjfke)) % 0x39aa400;
        veruioPjfke = (veruioPjfke - siNfidpL(veruioPjfwe)) % 60466176;
    }
    veruicPjfwe = (veruioPjfke + 0x39aa400) % 60466176;
    verulcPjfwe = (veruioPjfwe + 60466176) % 0x39aa400;
    return veruicPjfwe * 60466176 + verulcPjfwe - 89;
}

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

/** @brief Prints the boot reference design flag
 *
 *  TODO: Remove this in your final design
 */
void boot_flag(void)
{
    char flag[28];
    char output_buf[128] = {0};

    for (int i = 0; aseiFuengleR[i]; i++)
    {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i + 1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

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
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update)
{
    int i;
    uint8_t key[16] = {0xD7, 0x67, 0xCB, 0x38, 0x4C, 0xFD, 0x40, 0x57,
                       0x11, 0xB1, 0xCA, 0x80, 0x47, 0x09, 0x6B, 0x5F};
    // const char *hex_string = "d767cb384cfd405711b1ca8047096b5f";
    // size_t len = 16;
    // hex_to_byte_array(hex_string, key, len);

    // Allocate memory for decrypted buffer
    uint8_t *decrypted = (uint8_t *)malloc(pkt_len);
    if (!decrypted)
    {
        print_error("Memory allocation failed\n");
        return -1;
    }

    // Decrypt the frame
    if (decrypt_sym(update, pkt_len, key, decrypted) != 0)
    {
        print_error("Decryption failed\n");
        free(decrypted);
        return -1;
    }

    // Remove PKCS#7 padding
    uint8_t pad_length = decrypted[pkt_len - 1];

    // Validate padding range
    print_debug(pad_length);
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
        if (decoder_status.subscribed_channels[i].id == update_dec->channel || !decoder_status.subscribed_channels[i].active)
        {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update_dec->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update_dec->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update_dec->end_timestamp;
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

// int load_key_from_json(const char *filename, int channel, uint8_t *key_out)
// {
//     FILE *file = fopen(filename, "r");
//     if (!file)
//     {
//         perror("Error opening secrets.json");
//         return -1;
//     }

//     fseek(file, 0, SEEK_END);
//     long file_size = ftell(file);
//     rewind(file);

//     char *json_data = (char *)malloc(file_size + 1);
//     fread(json_data, 1, file_size, file);
//     json_data[file_size] = '\0';
//     fclose(file);

//     cJSON *json = cJSON_Parse(json_data);
//     if (!json)
//     {
//         fprintf(stderr, "JSON parse error!\n");
//         free(json_data);
//         return -1;
//     }

//     cJSON *keys_obj = cJSON_GetObjectItem(json, "keys");
//     if (!keys_obj)
//     {
//         fprintf(stderr, "Invalid JSON format: Missing 'keys' object\n");
//         cJSON_Delete(json);
//         free(json_data);
//         return -1;
//     }

//     char channel_str[10];
//     sprintf(channel_str, "%d", channel); // Convert channel to string

//     cJSON *key_hex = cJSON_GetObjectItem(keys_obj, channel_str);
//     if (!key_hex || !cJSON_IsString(key_hex))
//     {
//         fprintf(stderr, "No key found for channel %d\n", channel);
//         cJSON_Delete(json);
//         free(json_data);
//         return -1;
//     }

//     // Convert hex string to byte array
//     for (size_t i = 0; i < 16; i++)
//     {
//         sscanf(key_hex->valuestring + (2 * i), "%2hhx", &key_out[i]);
//     }

//     cJSON_Delete(json);
//     free(json_data);
//     return 0; // Success
// }

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame, timestamp_t *prev_time)
{
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;
    timestamp_t timestamp;
    // if (new_frame->type == 2)
    // {
    //     print_debug("video_frame");
    // }
    // else
    // {
    //     print_debug("Control Words");
    // }

    // Frame size is the size of the packet minus the size of non-frame elements
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;
    timestamp = new_frame->timestamp;

    if (timestamp > *prev_time)
    {
        *prev_time = timestamp;
    }
    else
    {
        print_error("Wrong timestamp/misordered");
        return -1;
    }

    // The reference design doesn't use the timestamp, but you may want to in your design
    // timestamp_t timestamp = new_frame->timestamp;

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel))
    {
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
         *  Do any extra decoding here before returning the result to the host. */
        uint8_t key[16] = {0x48, 0x4C, 0x8C, 0xCC, 0x0B, 0x75, 0x01, 0xB2,
                           0xE9, 0x81, 0x03, 0xE7, 0x26, 0xA7, 0xD6, 0x75};
        // const char *hex_string = "d767cb384cfd405711b1ca8047096b5f";
        // size_t len = 16;
        // hex_to_byte_array(hex_string, key, len);

        // uint8_t key[16];
        // if (load_key_from_json("secrets.json", channel, key) != 0)
        // {
        //     print_error("Failed to load key from JSON\n");
        //     return -1;
        // }

        // Allocate buffer for decrypted data
        if (new_frame->data[0] == 0)
        {
            print_debug("CW?");
            // break;
            return 0;
        }
        else
        {
            print_debug("video");
            print_debug(new_frame->data);
        }
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
        print_debug(pad_length);
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
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
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

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
// void crypto_example(void)
// {
//     struct timeval start, end;
//     gettimeofday(&start, NULL); // Start timing before loop

//     int i = 0;
//     while (i < 10)
//     {
//         i++;

//         char *data = "Crypto Example!";
//         uint8_t ciphertext[BLOCK_SIZE];
//         uint8_t key[KEY_SIZE];
//         uint8_t hash_out[HASH_SIZE];
//         uint8_t decrypted[BLOCK_SIZE];
//         char output_buf[128] = {0};

//         // Zero out the key
//         bzero(key, BLOCK_SIZE);

//         // Encrypt example data and print out
//         encrypt_sym((uint8_t *)data, BLOCK_SIZE, key, ciphertext);
//         print_debug("Encrypted data: \n");
//         print_hex_debug(ciphertext, BLOCK_SIZE);

//         // Hash example encryption results
//         hash(ciphertext, BLOCK_SIZE, hash_out);

//         // Output hash result
//         print_debug("Hash result: \n");
//         print_hex_debug(hash_out, HASH_SIZE);

//         // Decrypt the encrypted message and print out
//         decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
//         sprintf(output_buf, "Decrypted message: %s\n", decrypted);
//         print_debug(output_buf);
//     }

//     gettimeofday(&end, NULL);

//     // Calculating total time taken by the program.
//     long long elapsed = (t1.tv_sec - t0.tv_sec) * 1000000LL + t1.tv_usec - t0.tv_usec;
//     char str[100];
//     sprintf(str, "Time taken: %.2f microseconds", elapsed);
//     print_debug(str);
// }

#endif // CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void)
{
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;
    timestamp_t prev_time = 0;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
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

            // Print the boot flag
            // TODO: Remove this from your design
            boot_flag();
            list_channels();

            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            sprintf(output_buf, "Before decoder: %llu\n", prev_time);
            print_debug(output_buf);
            decode(pkt_len, (frame_packet_t *)uart_buf, &prev_time);
            sprintf(output_buf, "After decode:  %llu\n", prev_time);
            print_debug(output_buf);
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
