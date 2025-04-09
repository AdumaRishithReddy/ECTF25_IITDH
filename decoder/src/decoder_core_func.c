#include "decoder_core_func.h"
#include "decoder_dbg_func.h"
#include "decoder_types.h"

#include <stdint.h>
#include <stddef.h>

#include "status_led.h"

#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"
#include "simple_flash.h"

// TODO: Add some includes

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
volatile flash_entry_t decoder_status;

const byte_t rsa_private_master_key[/*$LEN_RSA_PRIV_KEY$*/] /*$RSA_PRIV_KEY$*/;
const byte_t aes_master_key[/*$LEN_AES_KEY$*/] /*$AES_KEY$*/;
const byte_t ecc_public_verif_key[/*$LEN_ECC_PUBL_KEY$*/] /*$ECC_PUBL_KEY$*/;
const byte_t eddsa_public_verif_key[/*$LEN_EDDSA_PUBL_KEY$*/] /*$EDDSA_PUBL_KEY$*/;

ecc_key ecc_sig_verifier;
mp_int r_component, s_component;

ed25519_key eddsa_sig_verifier;

char output_buf[128];

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/
int is_subscribed(const channel_id_t channel) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/**********************************************************
 ************ CRYPTOGRAPHIC SUPPORT FUNCTIONS *************
 **********************************************************/
 int initialize_frame_verifier_ecc(ecc_key* ecc_key_instance, 
                                    const byte_t *verification_key_der, 
                                    const unsigned int ver_key_len,
                                    mp_int *mp_r, mp_int *mp_s) {

    // Wolfcrypt initialization of the ECC Key structure
    wc_ecc_init(ecc_key_instance);

    // Parse ASN.1 DER key
    unsigned int iteration_idx = 0;
    int ret;

    ret = wc_EccPublicKeyDecode(verification_key_der, &iteration_idx, ecc_key_instance, ver_key_len);
    if (ret != 0) {
        wc_ecc_free(ecc_key_instance);
        snprintf(output_buf, 128, "Failed to decode ASN.1 DER key. Error code %d\n", ret);
        print_error(output_buf);
        return -1;
    }

    // Verify key is valid
    ret = wc_ecc_check_key(ecc_key_instance);
    if (ret != 0) {
        wc_ecc_free(ecc_key_instance);
        snprintf(output_buf, 128, "Imported key is invalid. Error code %d\n", ret);
        print_error(output_buf);
        return -1;
    }
    else {
        print_debug("Imported ECC key is valid\n");
    }

    mp_init(mp_r);
    mp_init(mp_s);

    return 0;
}




 int initialize_frame_verifier_eddsa(ed25519_key *ed25519_key_instance, 
                                    const byte_t *verification_key_raw, 
                                    const unsigned int ver_key_len) {

    int ret;

    // Wolfcrypt initialization of the Ed25519 Key structure
    ret = wc_ed25519_init(ed25519_key_instance);
    if (ret < 0) {
        wc_ed25519_free(ed25519_key_instance);
        snprintf(output_buf, 128, "Failed to initialize Ed25519 key. Error code %d\n", ret);
        print_error(output_buf);
        return -1;
    }

    // Parse ed25519 RAW key
    ret = wc_ed25519_import_public_ex(
        verification_key_raw, ver_key_len,
        ed25519_key_instance,
        1 /*Trusted or not*/);
    if (ret != 0) {
        wc_ed25519_free(ed25519_key_instance);
        snprintf(output_buf, 128, "Failed to decoder Ed25519 public key. Error code %d\n", ret);
        print_error(output_buf);
        return -1;
    }

    // Verify key is valid
    // ret = wc_ed25519_check_key(ed25519_key_instance);
    // if (ret != 0) {
    //     wc_ecc_free(ed25519_key_instance);
    //     snprintf(output_buf, 128, "Imported key is invalid. Error code %d\n", ret);
    //     print_error(output_buf);
    //     return -1;
    // }
    // else {
    //     print_debug("Imported Ed25519 key is valid\n");
    // }
    return 0;
}




int verify_frame_signature_ecc(const byte_t *frame_data, const uint32_t frame_data_len,
                         const byte_t *signature_buf, const uint32_t signature_len, 
                         const ecc_key* ecc_key_instance, 
                         mp_int *mp_r, mp_int *mp_s) {

    int ret;
    int is_signature_correct;
    byte_t hash_result[SIGNATURE_HASH_SIZE];

    // Read signature R and S component into mp_r and mp_s
    mp_read_unsigned_bin(mp_r, signature_buf, ECC_R_COMPONENT_LEN);
    mp_read_unsigned_bin(mp_s, signature_buf, ECC_S_COMPONENT_LEN);

    // Calculate the hash of encrypted frame
    hash(frame_data, frame_data_len, hash_result);

    // Verify signature
    ret = wc_ecc_verify_hash_ex(mp_r, mp_s, 
                                hash_result, SIGNATURE_HASH_SIZE, 
                                &is_signature_correct, 
                                ecc_key_instance);
    if (ret < 0) {
        snprintf(output_buf, 128, "Signature verification failed! Error code: %d\n", ret);
        print_error(output_buf);
        return -1;
    } else {
        // TODO: Remove this debug
        if(is_signature_correct) {
            print_debug("Signature verification successful\n");
            return 0;
        } else {
            print_debug("Bad signature!\n");
            return -1;
        }
    }

    return 0;
}




int verify_frame_signature_eddsa(const byte_t *frame_data, const uint32_t frame_data_len,
                         const byte_t *signature_buf, const uint32_t signature_len, 
                         const ed25519_key* ed25519_key_instance) {

    int ret;
    int is_signature_correct;

    ret = wc_ed25519_verify_msg(
            signature_buf, signature_len,         /* r/s encoded */
            frame_data, frame_data_len,           /* message */
            &is_signature_correct,                /* verification result 1=success */
            ed25519_key_instance                  /* key context */
        );
    if (ret != 0) {
        snprintf(output_buf, 128, "Signature verification failed! Error code: %d\n", ret);
        print_error(output_buf);
        return -1;
    } else {
        // TODO: Remove this debug
        if(is_signature_correct) {
            print_debug("Signature verification successful\n");
            return 0;
        } else {
            print_debug("Bad signature!\n");
            return -1;
        }
    }
}



int derive_control_word(const byte_t *sk_buf, 
                        const byte_t *iv_buf, 
                        byte_t *derived_control_word)
{
    if (sk_buf == NULL || 
        iv_buf == NULL || 
        derived_control_word == NULL
    ) {
        printf("Invalid input parameters\n");
        return -1;
    }

    int ret = wc_PBKDF2(derived_control_word, 
                        sk_buf, 
                        SUBS_KEY_LENGTH, 
                        iv_buf, 
                        PBKDF2_SALT_LENGTH, 
                        PBKDF2_ITERATIONS, 
                        CTRL_WRD_LENGTH, 
                        WC_SHA256);

    if (ret != 0) {
        printf("PBKDF2 key derivation failed! Error code: %d\n", ret);
        return -1;
    } else {
        printf("PBKDF2 key derived successfully\n");
        return 0;
    }
}




// TODO: pkt_len is dangerous TV controlled value
int decrypt_subscription_rsa(const pkt_len_t pkt_len, 
                            const byte_t *encr_update_packet, 
                            byte_t *decr_update_pkt, 
                            const size_t decrypted_buffer_size) {    

    // Decrypt the subscription packet
    int ret = decrypt_asym_rsa( 
                        encr_update_packet, 
                        pkt_len,
                        rsa_private_master_key, 
                        sizeof(rsa_private_master_key),
                        decr_update_pkt, decrypted_buffer_size);

    // Check for errors
    if (ret != 0) {
        snprintf(output_buf, 128, "RSA Subscription Decryption failed! Error code: %d\n", ret);
        print_error(output_buf);
        return -1;
    }

    return 0;
}





// TODO: pkt_len is dangerous TV controlled value
int decrypt_subscription_aes(const byte_t *encr_update_packet, 
                            const size_t pkt_len, 
                            byte_t *decr_update_pkt) {

    // Decrypt the subscription packet
    int ret = decrypt_sym(encr_update_packet, pkt_len, aes_master_key, decr_update_pkt);

    // Check for errors
    if (ret != 0) {
        snprintf(output_buf, 128, "AES Subscription Decryption failed! Error code: %d\n", ret);
        print_error(output_buf);
        return -1;
    }

    return 0;
}





int decrypt_frame_data(const byte_t *encr_frame_data, 
                        const byte_t *control_word, 
                        byte_t *decr_frame_data) {

    // Decrypt the frame data
    int ret = decrypt_sym(encr_frame_data, FRAME_SIZE, control_word, decr_frame_data);

    // Check for errors
    if (ret != 0) {
        snprintf(output_buf, 128, "AES Frame Decryption failed! Error code: %d\n", ret);
        print_error(output_buf);
        return -1;
    }

    return 0;
}


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
                            &decr_update_pkt, sizeof(subscription_update_packet_t))
#else
    decrypt_subscription_aes(encr_update_pkt, pkt_len, (byte_t *) &decr_update_pkt);
#endif

    // Check if somebody is tryng to updaate emergency channel
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

            snprintf(output_buf, 128, "Updated channel!  %u\n", decr_update_pkt.channel);
            print_debug(output_buf);

            // TODO: Remove this (prints SK and IV)
            // print_as_int(decr_update_pkt.subscription_key, 4);
            // print_as_int(decr_update_pkt.init_vector, 4);
            
            // TODO: Remove this (prints CID, STS and ETS)
            // snprintf(output_buf, 
            //             128, 
            //             " ID: %u\n START: %u\n END: %u\n", 
            //             decr_update_pkt.channel,
            //             decr_update_pkt.start_timestamp,
            //             decr_update_pkt.end_timestamp
            //             );
            // print_debug(output_buf);
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




//TODO: Remove frame count
uint32_t frame_count = 0;
int decode(const pkt_len_t pkt_len, const frame_packet_t *new_frame) {
    channel_id_t channel_id = new_frame -> channel;
    timestamp_t frame_ts = new_frame -> timestamp;

    // Throw an error if illegal channel data is being received
    if (!is_subscribed(channel_id)) {
        STATUS_LED_RED();
        snprintf(
            output_buf,
            128,
            "Receiving unsubscribed channel data.  %u\n", channel_id);
        print_error(output_buf);
        return -1;
    }

    for(int idx = 0; idx < MAX_CHANNEL_COUNT; idx++) {

        // Go ahead only if the channel id is found in our subscription
        if(decoder_status.subscribed_channels[idx].id != channel_id) {
            continue;
        }

        if (frame_ts <= decoder_status.subscribed_channels[idx].last_frame_timestamp) {
            snprintf(
                output_buf,
                128,
                "Out of order frame with timestamp  %u. Last seen timestamp is %u\n", 
                frame_ts, 
                decoder_status.subscribed_channels[idx].last_frame_timestamp
            );
            print_debug(output_buf);

            write_packet(DECODE_MSG, "ILLEGAL", 7);
            return 0;
        }

        // Generate a Control Word if it crosses the interval boundary
        if (frame_ts / CTRL_WRD_INTERVAL > decoder_status.subscribed_channels[idx].last_ctrl_wrd_gen_time) {
            
            //TODO: Remove this frame count debug print
            snprintf(
                output_buf,
                128,
                "Frame count since last control word is %u, %u\n", 
                frame_count,
                frame_ts
            );
            print_debug(output_buf);
            frame_count = 0;
            
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

            // TODO: Remove this (Prints CW on new CW)
            // print_as_int(derived_ctrl_wrd, 4);
            print_as_int(mixed_iv_buf, 4);

            // Update the last timestamp when you generated a Control Word
            decoder_status.subscribed_channels[idx].last_ctrl_wrd_gen_time = frame_ts / CTRL_WRD_INTERVAL;
        }


        // TODO: Verify frame signature
        // verify_frame_signature_ecc(new_frame -> data, FRAME_SIZE, 
        //                         new_frame -> sign, SIGNATURE_SIZE,
        //                         &ecc_sig_verifier,
        //                         &r_component,
        //                         &s_component);
        verify_frame_signature_eddsa(new_frame -> data, FRAME_SIZE, 
                                new_frame -> sign, SIGNATURE_SIZE,
                                &eddsa_sig_verifier);

        // Decrypt the frame
        byte_t decr_frame_data_buf[FRAME_SIZE];
        if (decrypt_frame_data(new_frame -> data, decoder_status.subscribed_channels[idx].control_word, decr_frame_data_buf) != 0) {
            return -1;
        }

        // Calculate padding
        uint8_t aes_pad_length = decr_frame_data_buf[FRAME_SIZE - 1];
        if (aes_pad_length != 15) {
            snprintf(output_buf, 128, "Invalid AES padding length! %d\n", aes_pad_length);
            print_error(output_buf);
            return -1;
        }
        uint8_t frame_pad_length = decr_frame_data_buf[FRAME_SIZE - aes_pad_length - 1];
        if (frame_pad_length == 0 || frame_pad_length > MAX_DECR_FRAME_SIZE) {
            snprintf(output_buf, 128, "Invalid Frame padding length! %d\n", frame_pad_length);
            print_error(output_buf);
            return -1;
        }

        // Write the decrypted frame data to UART
        frame_count++;
        write_packet(DECODE_MSG, decr_frame_data_buf, FRAME_SIZE - aes_pad_length - frame_pad_length);

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

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the Frame Verifier
    // ret = initialize_frame_verifier_ecc(&ecc_sig_verifier, ecc_public_verif_key, sizeof(ecc_public_verif_key), 
    //                                     &r_component, &s_component);
    ret = initialize_frame_verifier_eddsa(&eddsa_sig_verifier, eddsa_public_verif_key, sizeof(eddsa_public_verif_key));
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if verfiier fails to initialize, do not continue to execute
        while (1);
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}
