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

#include "mpu_armv7.h"
// #include "mxc_sys.h"
// #include "mxc_device.h"
// #include "mxc_delay.h"
// #include "nvic_table.h"
// #include "mxc.h"
// #include "board.h"
// #include "board.h"

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



void enable_mpu_access_rw(unsigned int region_num,
                        unsigned int base_register,
                        unsigned int region_size) {
    ARM_MPU_Disable();

    ARM_MPU_SetRegionEx(region_num, // Define a region number for the key
                        ARM_MPU_RBAR(region_num, base_register),    // Set base register, this will be pointer to where key is
                        ARM_MPU_RASR(0,  // Instruction access disable bit, 1= disable instruction fetches.
                                     ARM_MPU_AP_FULL,  // Data access permissions, allows you to configure read/write access for User and Privileged mode.
                                     0,  // Type extension field, allows you to configure memory access type, for example strongly ordered, peripheral.
                                     0,  // Region is shareable between multiple bus masters.
                                     0,  // Region is cacheable, i.e. its value may be kept in cache.
                                     0,  // Region is bufferable, i.e. using write-back caching. Cacheable but non-bufferable regions use write-through policy.
                                     0,  // Sub-region disable field.
                                     region_size     // Region size of the region to be configured
                                    )
                        );
    ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk);
}


void enable_mpu_access_ro(unsigned int region_num,
                        unsigned int base_register,
                        unsigned int region_size) {
    ARM_MPU_Disable();

    ARM_MPU_SetRegionEx(region_num, // Define a region number for the key
                        ARM_MPU_RBAR(region_num, base_register),    // Set base register, this will be pointer to where key is
                        ARM_MPU_RASR(0,  // Instruction access disable bit, 1= disable instruction fetches.
                                     ARM_MPU_AP_PRO,  // Data access permissions, allows you to configure read/write access for User and Privileged mode.
                                     0,  // Type extension field, allows you to configure memory access type, for example strongly ordered, peripheral.
                                     0,  // Region is shareable between multiple bus masters.
                                     0,  // Region is cacheable, i.e. its value may be kept in cache.
                                     0,  // Region is bufferable, i.e. using write-back caching. Cacheable but non-bufferable regions use write-through policy.
                                     0,  // Sub-region disable field.
                                     region_size     // Region size of the region to be configured
                                    )
                        );
    ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk);
}



void disable_mpu_access(unsigned int region_num,
                        unsigned int base_register,
                        unsigned int region_size) {
    ARM_MPU_Disable();

    ARM_MPU_SetRegionEx(region_num, // Define a region number for the key
                        ARM_MPU_RBAR(region_num, base_register),    // Set base register, this will be pointer to where key is
                        ARM_MPU_RASR(0,  // Instruction access disable bit, 1= disable instruction fetches.
                                     ARM_MPU_AP_NONE,  // Data access permissions, allows you to configure read/write access for User and Privileged mode.
                                     0,  // Type extension field, allows you to configure memory access type, for example strongly ordered, peripheral.
                                     0,  // Region is shareable between multiple bus masters.
                                     0,  // Region is cacheable, i.e. its value may be kept in cache.
                                     0,  // Region is bufferable, i.e. using write-back caching. Cacheable but non-bufferable regions use write-through policy.
                                     0,  // Sub-region disable field.
                                     region_size     // Region size of the region to be configured
                                    )
                        );
    ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk);
}
