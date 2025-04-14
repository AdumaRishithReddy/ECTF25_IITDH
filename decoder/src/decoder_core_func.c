#include "decoder_core_func.h"
#
#include "decoder_support_func.h"
#include "decoder_dbg_func.h"
#include "decoder_types.h"

#include <stdint.h>
#include <stddef.h>

#include "status_led.h"

#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"
#include "simple_flash.h"

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
volatile flash_entry_t decoder_status;

const byte_t aes_master_key[/*$LEN_AES_KEY$*/] /*$AES_KEY$*/;

const byte_t emergency_channel_key[/*$EMERGENCY_CHANNEL_KEY_LEN$*/] /*$EMERGENCY_CHANNEL_KEY$*/;

const byte_t emergency_channel_iv[/*$EMERGENCY_CHANNEL_IV_LEN$*/] /*$EMERGENCY_CHANNEL_IV$*/;

char output_buf_core[128];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/
int list_channels()
{
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint8_t i = 1; i < MAX_CHANNEL_COUNT; i++) {

        if (decoder_status.subscribed_channels[i].active) {

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




int update_subscription(const pkt_len_t pkt_len, const subscription_update_packet_t *encr_update_pkt) {

    if(pkt_len != MAX_SUBS_PKT_SIZE) {
        STATUS_LED_RED();
        snprintf(output_buf_core,
                128,
                "Failed to update subscription - Update packet too large/small: %u\n", 
                pkt_len
                );
        print_error(output_buf_core);
        return -1;
    }

    int ret;

    // Decrypt and store subscription data 
    subscription_update_packet_t decr_update_pkt;
    
    ret = decrypt_subscription_aes(encr_update_pkt, 
                                    MAX_SUBS_PKT_SIZE, 
                                    aes_master_key, 
                                    &decr_update_pkt);
    if(ret != 0) {
        return -1;
    }

    // Compute hash of the packet
    byte_t computed_hash[SUBS_HASH_SIZE];
    hash(&decr_update_pkt, 
            MAX_SUBS_PKT_SIZE - SUBS_PAD_SIZE - SUBS_HASH_SIZE, 
            computed_hash);


    print_as_int("COMPUTED__HASH: ", 16, computed_hash, 8);
    print_as_int("DEC_PACKT_HASH: ", 16, decr_update_pkt.hash, 8);
    
    // Verify integrity of the update packet
    ret = strncmp(decr_update_pkt.hash, computed_hash, SUBS_HASH_SIZE);
    if(ret != 0) {
        snprintf(
            output_buf_core,
            128,
            "Failed to update subscription - Packet is corrupt");
        print_error(output_buf_core);
        return -1;
    }

    // Check if decoder ID matches, else, discard packet
    if (decr_update_pkt.decoder_id != DECODER_ID) {
        STATUS_LED_RED();
        snprintf(output_buf_core,
                128,
                "Failed to update subscription - Update not valid for this decoder.");
        print_error(output_buf_core);
        return -1;
    }

    // Check if somebody is tryng to update emergency channel or default ID
    if (decr_update_pkt.channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    } else if (decr_update_pkt.channel == DEFAULT_CHANNEL_ID) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - default channel subscription detected\n");
        return -1;
    }

    // Find the first empty slot or slot with existing subscription in the subscription array
    // Fill it with updated subscription
    uint8_t i = 0;

    for (i = 1; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == decr_update_pkt.channel ||
            decoder_status.subscribed_channels[i].id == DEFAULT_CHANNEL_ID) {

            decoder_status.subscribed_channels[i].id = decr_update_pkt.channel;
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].start_timestamp = decr_update_pkt.start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = decr_update_pkt.end_timestamp;
            memcpy(decoder_status.subscribed_channels[i].channel_key, decr_update_pkt.channel_key, CHNL_KEY_LENGTH);
            memcpy(decoder_status.subscribed_channels[i].init_vector, decr_update_pkt.init_vector, INIT_VEC_LENGTH);
            
            wc_AesInit(&(decoder_status.subscribed_channels[i].frame_decryptor), 
                        NULL, 
                        INVALID_DEVID);
                        
            ret = wc_AesSetKey(&(decoder_status.subscribed_channels[i].frame_decryptor),
                                decoder_status.subscribed_channels[i].channel_key, 
                                CHNL_KEY_LENGTH, NULL, 
                                AES_ENCRYPTION);
                                
            if(ret != 0) {
                snprintf(output_buf_core,
                        128,
                        "Failed to update subscription. AES Context cannot be set. Channel %u\n", 
                        decr_update_pkt.channel
                        );

                print_error(output_buf_core);
                erase_subscription(decr_update_pkt.channel);
                return -1;
            }

            snprintf(output_buf_core, 128, "Updated channel!  %u\n", decr_update_pkt.channel);
            print_debug(output_buf_core);
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT) {
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



int erase_subscription(channel_id_t channel_id) {

    // Check if channel is subscribed to
    if (!is_subscribed(channel_id, &decoder_status)) {
        snprintf(
            output_buf_core,
            128,
            "Trying to erase an unsubscribed channel. Channel %u: Ignoring frame...\n", channel_id);
        print_error(output_buf_core);
        return -1;
    }

    // Erase channel if found (Do not erase ID)
    for(uint8_t idx = 0; idx < MAX_CHANNEL_COUNT; idx++) {

        if(decoder_status.subscribed_channels[idx].id != channel_id) {
            continue;
        }

        decoder_status.subscribed_channels[idx].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        decoder_status.subscribed_channels[idx].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        decoder_status.subscribed_channels[idx].active = false;

        memset(decoder_status.subscribed_channels[idx].channel_key, 0, CHNL_KEY_LENGTH);
        memset(decoder_status.subscribed_channels[idx].init_vector, 0, INIT_VEC_LENGTH);
        wc_AesFree(&(decoder_status.subscribed_channels[idx].frame_decryptor));

        // Do not set last frame timestamp to zero as we only decode monotonically increasing timestamps

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    return 0;
}





int decode(const pkt_len_t pkt_len, const frame_packet_t *new_frame) {

    if(pkt_len != MAX_FRAME_PKT_SIZE) {
        STATUS_LED_RED();
        snprintf(output_buf_core,
                128,
                "Failed to decode - Frame packet too large/small: %u\n", 
                pkt_len
                );
        print_error(output_buf_core);
        
        return -1;
    }

    channel_id_t channel_id = new_frame -> channel;
    timestamp_t frame_ts = new_frame -> timestamp;
    int ret;

    // Throw an error if illegal channel data is being received
    if (!is_subscribed(channel_id, &decoder_status)) {
        snprintf(
            output_buf_core,
            128,
            "Receiving unsubscribed channel data. Channel %u: Ignoring frame...\n", channel_id);
        print_error(output_buf_core);
        
        return -1;
    }

    for(int idx = 0; idx < MAX_CHANNEL_COUNT; idx++) {

        // ---------------------------------------------------
        // Checks for ensuring no pesky frames are decoded
        // ---------------------------------------------------

        // Go ahead only if the channel id is found in our subscription
        if(decoder_status.subscribed_channels[idx].id != channel_id) {
            continue;
        }

        // If frame timestamp crosses end timestamp, discard it, erase the subscription
        if (channel_id != EMERGENCY_CHANNEL &&
            frame_ts > decoder_status.subscribed_channels[idx].end_timestamp
        ) {
            snprintf(
                output_buf_core,
                128,
                "Subscrtiption ended. Erasing... Channel %u: Ignoring frame...\n", channel_id);
            print_error(output_buf_core);
            erase_subscription(channel_id);
            
            return -1;
        }

        // If frame timestamp is smaller than subscription timestamp, ignore it
        if (channel_id != EMERGENCY_CHANNEL &&
            frame_ts < decoder_status.subscribed_channels[idx].start_timestamp
        ) {
            snprintf(
                output_buf_core,
                128,
                "Receiving old frames not valid for subscription interval. Channel %u\n", channel_id);
            print_error(output_buf_core);
            
            return -1;
        }

        // Accept only monotonically increasing timestamps on frames
        // We have to make sure this is true for Channel 0 as well
        if (frame_ts <= decoder_status.subscribed_channels[idx].last_frame_timestamp) {
            snprintf(
                output_buf_core,
                128,
                "Out of order frame with timestamp %llu. Last seen timestamp is %llu on channel %u.\n",
                frame_ts,
                decoder_status.subscribed_channels[idx].last_frame_timestamp,
                channel_id
            );
            print_error(output_buf_core);
            
            return -1;
        } else {
            decoder_status.subscribed_channels[idx].last_frame_timestamp = frame_ts;
        }


        // ---------------------------------------------------
        // Decryption Process starts here
        // ---------------------------------------------------

        // Retrieve the Channel IV
        const byte_t *iv_buf = decoder_status.subscribed_channels[idx].init_vector;

        byte_t time_digest[32];
        byte_t mixed_iv_buf[INIT_VEC_LENGTH];
        char ts_str[32];

        // Create a digest of timestamp string to mix with the IV
        snprintf(ts_str, 32, "%llu", (unsigned long long)frame_ts);
        hash(ts_str, strlen(ts_str), time_digest);

        // Mix the IV with the digest
        for (int i = 0; i < INIT_VEC_LENGTH; i++) {
            mixed_iv_buf[i] = iv_buf[i] ^ time_digest[i];
        }
        mixed_iv_buf[INIT_VEC_LENGTH - 1] = 0x00; // Force set last byte to 0

        // Set the AES struct IV to Mixed IV
        Aes *frame_decryptor = &(decoder_status.subscribed_channels[idx].frame_decryptor);
        ret = wc_AesSetIV(frame_decryptor, mixed_iv_buf);
        if(ret != 0) {
            snprintf(
                output_buf_core,
                128,
                "Unable to set Init Vector: Channel %u: Ignoring frame...\n", channel_id);
            print_error(output_buf_core);
            
            return -1;
        }
        
        // Decrypt the frame (and also the hash, not visible here)
        frame_packet_t decrypted_frame;
        ret = decrypt_frame_data(frame_decryptor, new_frame -> data, decrypted_frame.data,  MAX_DECR_FRAME_SIZE);
        if(ret != 0) {
            print_error("AES Frame decrypt failed! - Data");
            return -1;
        }
        ret = decrypt_frame_data(frame_decryptor, new_frame -> hash, decrypted_frame.hash,  FRAME_HASH_SIZE);
        if(ret != 0) {
            print_error("AES Frame decrypt failed! - Hash");
            return -1;
        }

        // ---------------------------------------------------
        // Verify and finalize frame to display
        // ---------------------------------------------------

        // Verify hash is correct
        byte_t computed_hash[FRAME_HASH_SIZE];
        hash(decrypted_frame.data, MAX_DECR_FRAME_SIZE, computed_hash);

        ret = strncmp(decrypted_frame.hash, computed_hash, FRAME_HASH_SIZE);
        if(ret != 0) {
            snprintf(
                output_buf_core,
                128,
                "Frame hash does not match: Channel %u, Ignoring frame...\n",
                channel_id
            );
            print_error(output_buf_core);
            
            return -1;
        }
        

        // Calculate padding
        uint8_t pad_length = new_frame -> pad_length;
        if (pad_length >= MAX_DECR_FRAME_SIZE) {
            snprintf(output_buf_core, 128, "Invalid AES padding length! %d\n", pad_length);
            print_error(output_buf_core);
            
            return -1;
        }

        // Write the decrypted frame data to UART
        write_packet(DECODE_MSG, decrypted_frame.data, MAX_DECR_FRAME_SIZE - pad_length);

        return 0;
    }

    return -1;
}



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

        // Write in data for emergency channel
        subscription[0].id = EMERGENCY_CHANNEL;
        subscription[0].start_timestamp = 0;
        subscription[0].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        subscription[0].active = true;

        memcpy(subscription[0].channel_key, emergency_channel_key, CHNL_KEY_LENGTH);
        memcpy(subscription[0].init_vector, emergency_channel_iv, INIT_VEC_LENGTH);
        subscription[0].last_frame_timestamp = 0;

        // Write in data for all other channels
        for (int i = 1; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].id = DEFAULT_CHANNEL_ID;
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;

            memset(subscription[i].channel_key, 0, CHNL_KEY_LENGTH);
            memset(subscription[i].init_vector, 0, INIT_VEC_LENGTH);
            subscription[i].last_frame_timestamp = 0;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(decoder_status.subscribed_channels[i].active) {
            wc_AesInit(&(decoder_status.subscribed_channels[i].frame_decryptor), 
                        NULL, 
                        INVALID_DEVID);
                            
            ret = wc_AesSetKey(&(decoder_status.subscribed_channels[i].frame_decryptor),
                                decoder_status.subscribed_channels[i].channel_key, 
                                CHNL_KEY_LENGTH, NULL, 
                                AES_ENCRYPTION);
                                
            if(ret != 0) {
                snprintf(output_buf_core,
                        128,
                        "Initialization failed! AES Context cannot be set: Channel %u\n",
                        decoder_status.subscribed_channels[i].id
                );

                print_error(output_buf_core);
                erase_subscription(decoder_status.subscribed_channels[i].id);
            }
        }
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}