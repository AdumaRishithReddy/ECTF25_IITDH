#include "decoder_dbg_func.h"
#include "decoder_types.h"
#include "host_messaging.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>


void print_as_int(const byte_t *inp_buf, const size_t num_of_int) {
    int32_t *converted_inp = (int32_t *)inp_buf;
    char out_buf[128];
    size_t offset = 0;

    for (uint8_t i = 0; i < num_of_int; i++) {
        offset += snprintf(out_buf + offset, sizeof(out_buf) - offset, "%d%s",
                           converted_inp[i],
                           (i < num_of_int - 1) ? ", " : "");
        // Optionally check if offset reached the buffer capacity
        if (offset >= sizeof(out_buf)) {
            break;
        }
    }
    print_debug(out_buf);
}
