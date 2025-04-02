#!/bin/bash

# Create a backup of the original file
cp /decoder/src/decoder_core_func.c /out/decoder_core_func.c.bak

# Run the replace_keys.py script
python3 /decoder/build_scripts/replace_keys.py /decoder/src/decoder_core_func.c /global.secrets 0xDEADBEEF

# Run the make command
make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out

# Restore the backup of the original file
cp /out/decoder_core_func.c.bak /decoder/src/decoder_core_func.c
