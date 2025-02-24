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
import hashlib
import os
import json
from Crypto.Cipher import AES

class Encoder:
    idx=0
    def __init__(self, secrets: bytes):
        """
        You **may not** change the arguments or returns of this function!

        :param secrets: Contents of the secrets file generated by
            ectf25_design.gen_secrets
        """
        # TODO: parse your secrets data here and run any necessary pre-processing to
        #   improve the throughput of Encoder.encode

        # Load the json of the secrets file
        secrets = json.loads(secrets)
        

        # Load the example secrets for use in Encoder.encode
        # This will be "EXAMPLE" in the reference design"
        self.some_secrets = secrets["keys"]

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function

        This will be called for every frame that needs to be encoded before being
        transmitted by the satellite to all listening TVs

        You **may not** change the arguments or returns of this function!

        :param channel: 16b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode

        :returns: The encoded frame, which will be sent to the Decoder
        """
        # TODO: encode the satellite frames so that they meet functional and
        #  security requirements
        # self.idx+=1
        # if self.idx%2==0:
        #     frame="0Hello world".encode()
        #     return struct.pack("<IQ", channel, timestamp) + frame
        # IV=bytes.fromhex(os.urandom(16).hex()) 
        IV = bytes.fromhex("bf5f9e3e41d955339a8cfc6ec821a580")
        cw=hashlib.pbkdf2_hmac('sha256', bytes.fromhex(self.some_secrets.get(str(channel))), IV, 10000, dklen=16)
        print(cw.hex())
        key_hex = self.some_secrets.get(str(channel))
        # print(f"Key used for channel {channel}: {key_hex}")

        if key_hex is None:
            raise ValueError("No key found for channel")
        
        # key = bytes.fromhex(key_hex)
        # cipher = AES.new(key, AES.MODE_ECB)
        cipher = AES.new(cw, AES.MODE_ECB)
        # Ensure frame is padded to a multiple of 16 bytes (AES block size)
        pad_length = 16 - (len(frame) % 16)
        frame_padded = frame + bytes([pad_length] * pad_length)
        
        encrypted_frame = cipher.encrypt(frame_padded)
        
        return struct.pack("<IQ", channel, timestamp) + encrypted_frame

        # return struct.pack("<IQ", channel, timestamp) + frame


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
