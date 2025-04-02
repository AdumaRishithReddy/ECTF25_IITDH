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
from Crypto.Util.Padding import pad
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

signature_type = "ECC"

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

        self.signing_key = ECC.import_key(secrets["signing_key"])
        self.verification_key = ECC.import_key(secrets["verification_key"])
        self.signing_context = DSS.new(self.signing_key, 'fips-186-3')

        self.frame_count = 0
        self.current_control_word = {channel_no: None for channel_no in self.channel_details.keys()}
        self.prev_ts = {channel_no: 9999 for channel_no in self.channel_details.keys()}
        self.cipher_objects = {channel_no: None for channel_no in self.channel_details.keys()}


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

        # TODO: Remove this
        def print_as_int(data: bytes, label: str):
            out_str = label
            for i in range(0, 13, 4):
                part_int = int.from_bytes(data[i:i+4],  byteorder='little', signed=True)
                out_str += ' ' + str(part_int)

            print(out_str)

        # JSON keys are strings
        channel_str = str(channel)


        # -----------------------------------------------------------------
        # A new control word is generated
        #   1. at the start of the channel stream or
        #   2. when an interval boundary is crossed (here, 10000 units)
        # -----------------------------------------------------------------

        cw_interval = 10000000

        if self.current_control_word[channel_str] is None or timestamp // cw_interval > self.prev_ts[channel_str]:

            # Calculating Salt, IV and MixedIV
            timestamp_mod_bytes = str(timestamp // cw_interval).encode()
            time_digest = hashlib.sha256(timestamp_mod_bytes).digest()[:16]

            iv_hex = self.channel_details[channel_str]["init_vector"]
            iv = bytes.fromhex(iv_hex)

            mixed_iv = bytes(a ^ b for a, b in zip(time_digest, iv))

            # Retreiving the channel key
            channel_key_hex = self.channel_details[channel_str]["channel_key"]
            channel_key = bytes.fromhex(channel_key_hex)

            # Generating a new control word
            self.current_control_word[channel_str] = hashlib.pbkdf2_hmac('sha256',
                                                                     channel_key,
                                                                     mixed_iv,
                                                                     1000,
                                                                     dklen=16)

            # Keeping track of when the last control word was generated
            self.prev_ts[channel_str] = timestamp // cw_interval

            # Creating new AES cipher object
            self.cipher_objects[channel_str] = AES.new(self.current_control_word[channel_str],
                                                   AES.MODE_ECB)

            print_as_int(self.current_control_word[channel_str], 'CW: ')

        self.frame_count+=1

        # Ensure frame is padded to a multiple of 16 bytes (AES block size)
        padded_frame = pad(frame, AES.block_size)
        # print(len(frame), len(padded_frame), len(padded_frame) - len(frame))

        # Encrypt the frame
        encrypted_frame = self.cipher_objects[channel_str].encrypt(padded_frame)

        # Hash the encrypted frame and sign
        eframe_hash_obj = SHA256.new(encrypted_frame)
        eframe_signature = self.signing_context.sign(eframe_hash_obj)

        # print(eframe_hash_obj.hexdigest())
        # print(eframe_signature.hex())
        # print("---------------------------------------------------")

        # pubkey_der = self.verification_key.export_key(format="DER")
        # print(", ".join(f"0x{b:02X}" for b in pubkey_der))
        # print("---------------")


        # Create the final frame that will be sent
        sgn_enc_frame = eframe_signature + encrypted_frame

        # Return the signed encrypted frame
        return struct.pack("<IQ", channel, timestamp) + sgn_enc_frame

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
