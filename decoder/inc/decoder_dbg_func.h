#ifndef DECODER_DBG_FUNC_H
#define DECODER_DBG_FUNC_H

#include <stdint.h>
#include <stddef.h>

#include "decoder_types.h"



/**
 * @brief Interprets a byte buffer as an array of 32-bit integers and prints them.
 *
 * This function casts the input byte buffer to an array of 32-bit integers and
 * outputs their values as a comma-separated string using print_debug().
 *
 * @param inp_buf Pointer to the input buffer containing the byte data.
 * @param num_of_int Number of 32-bit integers to print from the buffer.
 */
void print_as_int(const byte_t *inp_buf, const size_t num_of_int);

void print_hex_deb(const char *label, uint8_t *data, size_t len);

#endif