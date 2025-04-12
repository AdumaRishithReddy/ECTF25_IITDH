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

timestamp_t last_frame_timestamp_emergency;

ed25519_key eddsa_sig_verifier;
const byte_t rsa_private_master_key[/*$LEN_RSA_PRIV_KEY$*/] /*$RSA_PRIV_KEY$*/;
const byte_t aes_master_key[/*$LEN_AES_KEY$*/] /*$AES_KEY$*/;
const byte_t eddsa_public_verif_key[/*$LEN_EDDSA_PUBL_KEY$*/] /*$EDDSA_PUBL_KEY$*/;

char output_buf_core[128];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/
int list_channels()
{
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint8_t i = 0; i < MAX_CHANNEL_COUNT; i++) {

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




int update_subscription(const pkt_len_t pkt_len, const byte_t *encr_update_pkt) {

    // Create buffer for writing subscription data
    subscription_update_packet_t decr_update_pkt;

#ifdef USERSA
    decrypt_subscription_rsa(pkt_len, encr_update_pkt, 
                            rsa_private_master_key, sizeof(rsa_private_master_key), &decr_update_pkt, sizeof(subscription_update_packet_t))
#else
    decrypt_subscription_aes(encr_update_pkt, pkt_len, aes_master_key, (byte_t *)&decr_update_pkt);
#endif


    // Check if decoder ID matches, else, discard packet
    if (decr_update_pkt.decoder_id != DECODER_ID) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - Update not valid for this decoder\n");
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

    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == decr_update_pkt.channel ||
            decoder_status.subscribed_channels[i].id == DEFAULT_CHANNEL_ID) {

            decoder_status.subscribed_channels[i].id = decr_update_pkt.channel;
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].start_timestamp = decr_update_pkt.start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = decr_update_pkt.end_timestamp;
            memcpy(decoder_status.subscribed_channels[i].subscription_key, decr_update_pkt.subscription_key, SUBS_KEY_LENGTH);
            memcpy(decoder_status.subscribed_channels[i].init_vector, decr_update_pkt.init_vector, INIT_VEC_LENGTH);

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



void erase_subscription(uint8_t idx) {
    decoder_status.subscribed_channels[idx].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    decoder_status.subscribed_channels[idx].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    decoder_status.subscribed_channels[idx].active = false;

    memset(decoder_status.subscribed_channels[idx].subscription_key, 0, SUBS_KEY_LENGTH);
    memset(decoder_status.subscribed_channels[idx].init_vector, 0, INIT_VEC_LENGTH);
    memset(decoder_status.subscribed_channels[idx].control_word, 0, INIT_VEC_LENGTH);
    decoder_status.subscribed_channels[idx].last_ctrl_wrd_gen_time = 0;

    // Do not set last frame timestamp to zero as we have to have monotonically increasing timestamps
    // decoder_status.subscribed_channels[idx].last_frame_timestamp = 0;

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
}



int decode_emergency_channel(const pkt_len_t pkt_len, const frame_packet_t *new_frame) {
    channel_id_t channel_id = new_frame -> channel;
    timestamp_t frame_ts = new_frame -> timestamp;
    int ret;


    // Accept only monotonically increasing timestamps on frames
    if (frame_ts <= last_frame_timestamp_emergency) {
        snprintf(
            output_buf_core,
            128,
            "Out of order frame with timestamp %u. Last seen timestamp is %u on channel %u, Ignoring frame...\n", 
            frame_ts, 
            last_frame_timestamp_emergency,
            EMERGENCY_CHANNEL
        );
        print_debug(output_buf_core);
        return -1;
    } else {
        last_frame_timestamp_emergency = frame_ts;
    }

    // Verify signature of emergency channel
    ret = verify_frame_signature_eddsa(new_frame -> data, FRAME_SIZE, 
                                    new_frame -> sign, SIGNATURE_SIZE,
                                    &eddsa_sig_verifier);
    if(ret != 0) {
        return -1;
    }

    // Calculate padding
    uint8_t outer_pad_length = new_frame -> data[FRAME_SIZE - 1];
    if (outer_pad_length != 15) {
        snprintf(output_buf_core, 128, "Invalid AES padding length! %d\n", outer_pad_length);
        print_debug(output_buf_core);
        return -1;
    }
    uint8_t inner_pad_length = new_frame -> data[FRAME_SIZE - outer_pad_length - 1];
    if (inner_pad_length == 0 || inner_pad_length > MAX_DECR_FRAME_SIZE) {
        snprintf(output_buf_core, 128, "Invalid Frame padding length! %d\n", inner_pad_length);
        print_debug(output_buf_core);
        return -1;
    }

    // Write the decrypted frame data to UART
    write_packet(DECODE_MSG, new_frame -> data, FRAME_SIZE - outer_pad_length - inner_pad_length);

    return 0;
}



int decode(const pkt_len_t pkt_len, const frame_packet_t *new_frame) {
    channel_id_t channel_id = new_frame -> channel;
    timestamp_t frame_ts = new_frame -> timestamp;
    int ret;

    // Throw an error if illegal channel data is being received
    if (!is_subscribed(channel_id, &decoder_status)) {
        snprintf(
            output_buf_core,
            128,
            "Receiving unsubscribed channel data. Channel %u: Ignoring frame...\n", channel_id);
        print_debug(output_buf_core);
        return -1;
    }


    if (channel_id == EMERGENCY_CHANNEL) {
        int ret = decode_emergency_channel(pkt_len, new_frame);
        return ret;
    }

    for(int idx = 0; idx < MAX_CHANNEL_COUNT; idx++) {
        // Go ahead only if the channel id is found in our subscription
        if(decoder_status.subscribed_channels[idx].id != channel_id) {
            continue;
        }

        // If frame timestamp crosses end timestamp, discard it, erase the subscription
        if (frame_ts > decoder_status.subscribed_channels[idx].end_timestamp) {
            snprintf(
                output_buf_core,
                128,
                "Erasing subscription. Channel %u: Ignoring frame...\n", channel_id);
            print_debug(output_buf_core);
            erase_subscription(idx);
            return -1;
        }

        // If frame timestamp is smaller than subscription timestamp, ignore it
        if (frame_ts < decoder_status.subscribed_channels[idx].start_timestamp) {
            snprintf(
                output_buf_core,
                128,
                "Receiving frames not valid for subscription interval. Channel %u: Ignoring frame...\n", channel_id);
            print_debug(output_buf_core);
            return -1;
        }

        // Accept only monotonically increasing timestamps on frames
        if (frame_ts <= decoder_status.subscribed_channels[idx].last_frame_timestamp) {
            snprintf(
                output_buf_core,
                128,
                "Out of order frame with timestamp %u. Last seen timestamp is %u on channel %u, Ignoring frame...\n", 
                frame_ts, 
                decoder_status.subscribed_channels[idx].last_frame_timestamp,
                channel_id
            );
            print_debug(output_buf_core);
            return -1;
        } else {
            decoder_status.subscribed_channels[idx].last_frame_timestamp = frame_ts;
        }

        // Generate a Control Word if it crosses the interval boundary
        if (frame_ts / CTRL_WRD_INTERVAL > decoder_status.subscribed_channels[idx].last_ctrl_wrd_gen_time) {
            
            byte_t time_digest[32];
            byte_t mixed_iv_buf[INIT_VEC_LENGTH];
            byte_t derived_ctrl_wrd[CTRL_WRD_LENGTH];
            char ts_str[32];

            // Retrieve the SK and IV
            const byte_t *sk_buf = decoder_status.subscribed_channels[idx].subscription_key;
            const byte_t *iv_buf = decoder_status.subscribed_channels[idx].init_vector;

            // Create a digest of timestamp string to mix with the IV
            snprintf(ts_str, 32, "%llu", (unsigned long long)(frame_ts / CTRL_WRD_INTERVAL));
            hash(ts_str, strlen(ts_str), time_digest);

            // Mix the IV with the digest
            for (int i = 0; i < INIT_VEC_LENGTH; i++) {
                mixed_iv_buf[i] = iv_buf[i] ^ time_digest[i];
            }

            // Derive and write control word to Decoder Status structure
            derive_control_word(sk_buf, mixed_iv_buf, derived_ctrl_wrd);
            memcpy(decoder_status.subscribed_channels[idx].control_word, derived_ctrl_wrd, CTRL_WRD_LENGTH);

            // Update the last timestamp when you generated a Control Word
            decoder_status.subscribed_channels[idx].last_ctrl_wrd_gen_time = frame_ts / CTRL_WRD_INTERVAL;

            flash_simple_erase_page(FLASH_STATUS_ADDR);
            flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
        }

        // Verify signature before decryption
        ret = verify_frame_signature_eddsa(new_frame -> data, FRAME_SIZE, 
                                new_frame -> sign, SIGNATURE_SIZE,
                                &eddsa_sig_verifier);
        if(ret != 0) {
            return -1;
        }

        // Decrypt the frame
        byte_t decr_frame_data_buf[FRAME_SIZE];
        ret = decrypt_frame_data(new_frame -> data, decoder_status.subscribed_channels[idx].control_word, decr_frame_data_buf);
        if(ret != 0) {
            return -1;
        }

        // Calculate padding
        uint8_t outer_pad_length = decr_frame_data_buf[FRAME_SIZE - 1];
        if (outer_pad_length != 15) {
            snprintf(output_buf_core, 128, "Invalid AES padding length! %d\n", outer_pad_length);
            print_debug(output_buf_core);
            return -1;
        }
        uint8_t inner_pad_length = decr_frame_data_buf[FRAME_SIZE - outer_pad_length - 1];
        if (inner_pad_length == 0 || inner_pad_length > MAX_DECR_FRAME_SIZE) {
            snprintf(output_buf_core, 128, "Invalid Frame padding length! %d\n", inner_pad_length);
            print_debug(output_buf_core);
            return -1;
        }

        // Write the decrypted frame data to UART
        write_packet(DECODE_MSG, decr_frame_data_buf, FRAME_SIZE - outer_pad_length - inner_pad_length);

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

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){

            subscription[i].id = DEFAULT_CHANNEL_ID;
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;

            memset(subscription[i].subscription_key, 0, SUBS_KEY_LENGTH);
            memset(subscription[i].init_vector, 0, INIT_VEC_LENGTH);
            memset(subscription[i].control_word, 0, INIT_VEC_LENGTH);
            subscription[i].last_ctrl_wrd_gen_time = 0;
            subscription[i].last_frame_timestamp = 0;
        }

        last_frame_timestamp_emergency = 0;

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the frame signature verifier
    ret = initialize_frame_verifier_eddsa(&eddsa_sig_verifier, eddsa_public_verif_key, sizeof(eddsa_public_verif_key));
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if verfiier fails to initialize, do not continue to execute
        while (1);
