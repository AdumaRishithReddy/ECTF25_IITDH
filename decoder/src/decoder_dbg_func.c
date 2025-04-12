#include "decoder_dbg_func.h"
#include "decoder_types.h"
#include "host_messaging.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>


void print_as_int(const char *label, const size_t label_size, const byte_t *inp_buf, const size_t num_of_int) {
    int32_t *converted_inp = (int32_t *)inp_buf;
    char out_buf[128];
    size_t offset = label_size;

    memcpy(out_buf, label, label_size);

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
void print_hex_deb(const char *label, uint8_t *data, size_t len)
{
    char buffer[len * 2 + 50]; // Buffer to store formatted output
    char *ptr = buffer;

    ptr += sprintf(ptr, "%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        ptr += sprintf(ptr, "%02X", data[i]);
    }

    print_debug(buffer); // Print the formatted hex output
}