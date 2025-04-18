#include "decoder_support_func.h"


#include <wolfssl/wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfssl/wolfcrypt/hash.h>
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
    char output_buf_support[128];

    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (uint8_t i = 1; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status -> subscribed_channels[i].id == channel && decoder_status -> subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/**********************************************************
 ************ CRYPTOGRAPHIC SUPPORT FUNCTIONS *************
 **********************************************************/
int decrypt_subscription_aes(const byte_t *encr_update_packet, 
                            const size_t pkt_len, 
                            const byte_t *aes_master_key,
                            byte_t *decr_update_pkt) {

    char output_buf_support[128];

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


int decrypt_frame_data(Aes * frame_decryptor,
                        const byte_t *encr_frame_data, 
                        byte_t *decr_frame_data,
                        const size_t data_len) {

    // Decrypt the frame data
    wc_AesCtrEncrypt(frame_decryptor, decr_frame_data, encr_frame_data, data_len);
    return 0;
}
