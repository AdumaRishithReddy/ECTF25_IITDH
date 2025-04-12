#include "decoder_support_func.h"

#include <wolfssl/wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfssl/wolfcrypt/integer.h>
#include "wolfssl/wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfssl/wolfcrypt/hash.h"
#include <wolfssl/wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfssl/wolfcrypt/asn_public.h>

#include "host_messaging.h"
#include "decoder_types.h"
#include "decoder_dbg_func.h"
#include "simple_crypto.h"

#include <stddef.h>

char output_buf_support[128];

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/
int is_subscribed(const channel_id_t channel, const flash_entry_t *decoder_status) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status -> subscribed_channels[i].id == channel && decoder_status -> subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/**********************************************************
 ************ CRYPTOGRAPHIC SUPPORT FUNCTIONS *************
 **********************************************************/

 int initialize_frame_verifier_eddsa(ed25519_key *ed25519_key_instance, 
                                    const byte_t *verification_key_raw, 
                                    const unsigned int ver_key_len) {

    int ret;

    // Wolfcrypt initialization of the Ed25519 Key structure
    ret = wc_ed25519_init(ed25519_key_instance);
    if (ret < 0) {
        wc_ed25519_free(ed25519_key_instance);
        snprintf(output_buf_support, 128, "Failed to initialize Ed25519 key. Error code %d\n", ret);
        print_error(output_buf_support);
        return -1;
    }

    // Parse ed25519 RAW key
    ret = wc_ed25519_import_public(
        verification_key_raw, ver_key_len,
        ed25519_key_instance);
    if (ret != 0) {
        wc_ed25519_free(ed25519_key_instance);
        snprintf(output_buf_support, 128, "Failed to decode Ed25519 public key. Error code %d\n", ret);
        print_error(output_buf_support);
        return -1;
    }
    return 0;
}




int verify_frame_signature_eddsa(const byte_t *frame_data, const uint32_t frame_data_len,
                         const byte_t *signature_buf, const uint32_t signature_len, 
                         const ed25519_key* ed25519_key_instance) {

    int ret;
    int is_signature_correct;

    ret = wc_ed25519ph_verify_msg(
            signature_buf, signature_len,         /* r/s encoded */
            frame_data, frame_data_len,           /* message */
            &is_signature_correct,                /* verification result 1=success */
            ed25519_key_instance,                 /* key */
            "00000000", 8                         /* context and context len */
        );
    if (ret != 0) {
        snprintf(output_buf_support, 128, "EdDSA verify failed! Error code: %d\n", ret);
        print_debug(output_buf_support);
        return -1;
    } else {
        if(is_signature_correct) {
            // print_debug("Signature verification successful\n");
            return 0;
        } else {
            print_debug("Bad signature! Ignoring frame...\n");
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
        snprintf(output_buf_support, 128, "PBKDF2 key derivation failed! Error code: %d\n", ret);
        print_debug(output_buf_support);
        return -1;
    } else {
        // print_debug("PBKDF2 key derived successfully\n");
        return 0;
    }
}



// TODO: pkt_len is dangerous TV controlled value
int decrypt_subscription_rsa(const pkt_len_t pkt_len, 
                            const byte_t *encr_update_packet, 
                            const byte_t *rsa_private_master_key,
                            const size_t rsa_private_master_key_len,
                            byte_t *decr_update_pkt, 
                            const size_t decrypted_buffer_size) {    

    // Decrypt the subscription packet
    int ret = decrypt_asym_rsa( 
                        encr_update_packet, 
                        pkt_len,
                        rsa_private_master_key, 
                        rsa_private_master_key_len,
                        decr_update_pkt, decrypted_buffer_size);

    // Check for errors
    if (ret != 0) {
        snprintf(output_buf_support, 128, "RSA Subscription Decryption failed! Error code: %d\n", ret);
        print_error(output_buf_support);
        return -1;
    }

    return 0;
}





// TODO: pkt_len is dangerous TV controlled value
int decrypt_subscription_aes(const byte_t *encr_update_packet, 
                            const size_t pkt_len, 
                            const byte_t *aes_master_key,
                            byte_t *decr_update_pkt) {

    // Decrypt the subscription packet
    int ret = decrypt_sym(encr_update_packet, pkt_len, aes_master_key, decr_update_pkt);

    // Check for errors
    if (ret != 0) {
        snprintf(output_buf_support, 128, "AES Subscription Decryption failed! Error code: %d\n", ret);
        print_error(output_buf_support);
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
        snprintf(output_buf_support, 128, "AES Frame Decryption failed! Error code: %d\n", ret);
        print_debug(output_buf_support);
        return -1;
    }

    return 0;
}
