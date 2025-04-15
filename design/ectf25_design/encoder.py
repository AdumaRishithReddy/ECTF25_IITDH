"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import struct
import os
import json
import hashlib

from Crypto.Cipher import AES
from Crypto.Util import Counter



def print_as_int(label: str, data: bytes):
    """
    Debug function used to check keys
    Prints keys as 4 byte integers
    (only works if key size is multiple of 4)
    """
    out_str = label
    for i in range(0, len(data) - 3, 4):
        part_int = int.from_bytes(data[i:i+4],  byteorder='little', signed=True)
        out_str += ' ' + str(part_int)

    print(out_str)


class Encoder:

    def __init__(self, secrets: bytes):
        """
        You **may not** change the arguments or returns of this function!

        :param secrets: Contents of the secrets file generated by
            ectf25_design.gen_secrets
        """

        # Load the json of the secrets file
        secrets = json.loads(secrets)


        # Load the secrets for use in Encoder.encode
        self.channel_details = secrets["channel_details"]
        self.decoder_details = secrets["decoder_details"]

        # Keep track of frame count for debugging
        self.frame_count = 0


    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function

        This will be called for every frame that needs to be encoded before being
        transmitted by the satellite to all listening TVs

        :param channel: 32b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode

        :returns: The encoded frame, which will be sent to the Decoder
        """
        if len(frame) > 64:
            raise ValueError(f"Frame length ({len(frame)}) must be less than or equal to 64")

        # JSON keys are strings
        channel_str = str(channel)


        # Since we expect all encoded frames to be of same size (at the decoder)
        # we artificially inflate all frames to 64B.
        pad_length = 64 - len(frame)
        padded_frame = frame + os.urandom(pad_length)

        # Append a 32B hash to the frame
        frame_hash = hashlib.sha256(padded_frame).digest()
        frame_with_hash = padded_frame + frame_hash

        # Retreive channel key
        channel_key_hex_str = self.channel_details[channel_str]["channel_key"]
        channel_key = bytes.fromhex(channel_key_hex_str)

        # Retrieve channel init vector of 16B
        channel_iv_hex_str =  self.channel_details[channel_str]["channel_iv"]
        channel_iv_bytes = bytes.fromhex(channel_iv_hex_str)

        # Create a hash of string of timestamp
        timestamp_str = str(timestamp)
        timestamp_hash_bytes = hashlib.sha256(timestamp_str.encode('utf-8')).digest()[:16]

        # Create an initial value (CTR mode) of 16B
        # Here, initial value is name mixed_init_vector as
        # on wolfCrypt, the IV is used as the initial value
        mixed_init_vector = bytes([int(timestamp_hash_bytes[i]) ^ int(channel_iv_bytes[i]) for i in range(16)])

        # Create a new counter
        #
        # Counter Structure:
        # +-------+---------------+
        # | nonce | counter value |
        # +-------+---------------+

        # Create an AES Cipher object
        cipher_object = AES.new(channel_key,
                            AES.MODE_CTR,
                            nonce = mixed_init_vector[0:15],
                            initial_value = b'\x00')

        # Encrypt the frame with the hash
        encrypted_frame = cipher_object.encrypt(frame_with_hash)


        # Verify if frame was encrypted properly
        # cipher_object_verify = AES.new(channel_key,
        #                     AES.MODE_CTR,
        #                     nonce = mixed_init_vector[0:15],
        #                     initial_value = b'\x00')
        # decrypted_frame = cipher_object_verify.decrypt(encrypted_frame[0:64])
        # decrypted_hash = cipher_object_verify.decrypt(encrypted_frame[64:])
        #
        # if decrypted_hash != frame_hash:
        #     print(decrypted_hash)
        #     print(frame_hash)
        #     print("Computed hash and decrypted hash do not match!")

        # Debug frame count
        self.frame_count += 1

        # Return the signed encrypted frame
        return struct.pack("<IQ", channel, timestamp) + bytes([pad_length]) + encrypted_frame

def main():
    """A test main to one-shot encode a frame

    This function is only for your convenience and will not be used in the final design.

    After pip-installing, you should be able to call this with:
        python3 -m ectf25_design.encoder path/to/test.secrets 1 "frame to encode" 100
    """
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))


if __name__ == "__main__":
    main()
