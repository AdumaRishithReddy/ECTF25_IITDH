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
#include <stdint.h>
#include <unistd.h>

#include "mxc.h"
#include "mxc_device.h"
#include "mxc_delay.h"
#include "mxc_sys.h"
#include "nvic_table.h"
#include "core_cm4.h"
#include "status_led.h"
#include "board.h"

#include "simple_uart.h"
#include "simple_crypto.h"
#include "host_messaging.h"

#include "decoder_types.h"
#include "decoder_core_func.h"

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void)
{
    // TODO: Remove WolfSSL Debugging ON
    wolfSSL_Debugging_ON();
    wolfCrypt_Init();

    char output_buf[128] = {0};
    byte_t uart_buf[256];

    msg_type_t cmd;
    int result;
    
    pkt_len_t pkt_len;

    init();
    print_debug("Decoder Booted!\n");

    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {
        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (byte_t *)uart_buf);
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
