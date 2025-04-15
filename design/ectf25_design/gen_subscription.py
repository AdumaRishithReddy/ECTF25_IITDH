"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import os
import argparse
import json
from pathlib import Path
import struct
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from loguru import logger

verify_before_write = False

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

def load_keys(secrets, device_id, channel_str):
    """Load the master key, channel key, and initialization vector (IV) from the secrets.

    :param secrets: Dictionary containing channel and decoder details.
    :param device_id: String representation of the device ID.
    :param channel_str: String representation of the channel.
    :return: Tuple containing the master key encoder, channel key, and IV.
    :raises ValueError: If the master key, channel key, or IV is not found.
    """

    # Load channel and decoder details
    channel_details = secrets["channel_details"]
    decoder_details = secrets["decoder_details"]

    # Load the random 16 bytes used to create master key
    random_16_bytes = decoder_details["random_16_bytes"]
    if random_16_bytes is None:
        raise ValueError("No Random 16 bytes found")

    random_16_bytes = bytes.fromhex(random_16_bytes)

    # Load channel key
    channel_key_hex_str = channel_details[channel_str]["channel_key"]
    if channel_key_hex_str is None:
        raise ValueError("No key found for channel")

    # Load the IV
    iv_hex_str = channel_details[channel_str]["channel_iv"]
    if iv_hex_str is None:
        raise ValueError("No IV found for channel")

    master_key = hashlib.pbkdf2_hmac('sha256',
                                     random_16_bytes,
                                     device_id.to_bytes(4, byteorder = 'big'),
                                     1000,
                                     dklen = 16)


    return master_key, channel_key_hex_str, iv_hex_str

def create_subscription_struct(device_id, start, end, channel, channel_key_hex_str, iv_hex_str):
    """Create a packed binary structure for the subscription data.

    :param device_id: Device ID of the Decoder.
    :param start: First timestamp the subscription is valid for.
    :param end: Last timestamp the subscription is valid for.
    :param channel: Channel to enable.
    :param channel_key_hex_str: Hexadecimal string representation of the channel key.
    :param iv_hex_str: Hexadecimal string representation of the initialization vector (IV).
    :return: Packed binary data representing the subscription.
    """

    # Pack and return subscription.bin data
    channel_key_bytes = bytes.fromhex(channel_key_hex_str)
    init_vector_bytes = bytes.fromhex(iv_hex_str)

    return struct.pack(f"<IQQI16s16s",
                       device_id,
                       start,
                       end,
                       channel,
                       channel_key_bytes,
                       init_vector_bytes)

def encrypt_subscription_struct(master_key_encoder, packed_data):
    """Encrypt the packed subscription data using the master key encoder.

    :param master_key_encoder: The master key used for encryption.
    :param packed_data: The packed binary data to be encrypted.
    :return: Encrypted subscription data.
    """

    # Create a cipher for encryption
    cipher = AES.new(master_key_encoder, AES.MODE_ECB)
    packed_padded = pad(packed_data, AES.block_size)
    return cipher.encrypt(packed_padded)

def verify_encrypted_sub(master_key_decoder, encrypted_data, expected_values):
    """Verify the decrypted subscription data against expected values.

    :param master_key_decoder: String representation of master key (decoder).
    :param encrypted_data: Encrypted subscription data to be verified.
    :param expected_values: Dictionary of expected values for verification.
    :raises AssertionError: If any of the unpacked values do not match the expected values.
    """

    # Decrypt based on algorithm used
    cipher_decoder = AES.new(master_key_decoder, AES.MODE_ECB)
    decrypted_data = cipher_decoder.decrypt(encrypted_data)
    decrypted_data = unpad(decrypted_data, AES.block_size)

    unpacked_data = struct.unpack(f"<IQQI16s16s32s", decrypted_data)

    # Verify each value
    for key, expected_value in expected_values.items():
        actual_value = unpacked_data[["device_id", "start", "end",
                                      "channel", "channel_key", "iv", "hash"].index(key)]
        assert actual_value == expected_value, f"{key} does not match: expected {expected_value}, got {actual_value}"

        logger.debug(f"Verified {actual_value}")

def gen_subscription(secrets, device_id, start, end, channel):
    """Generate the contents of a subscription.

    The output of this will be passed to the Decoder using ectf25.tv.subscribe

    :param secrets: Contents of the secrets file generated by ectf25_design.gen_secrets
    :param device_id: Device ID of the Decoder
    :param start: First timestamp the subscription is valid for
    :param end: Last timestamp the subscription is valid for
    :param channel: Channel to enable
    """

    logger.debug(f"Device id: {device_id}")

    # JSON keys are strings
    device_id_str = str(device_id)
    channel_str = str(channel)

    # Load the secrets
    secrets = json.loads(secrets)

    # Load keys
    master_key_encoder, channel_key_hex_str, iv_hex_str = load_keys(secrets, device_id, channel_str)

    # Create the subscription struct
    packed_data = create_subscription_struct(device_id, start, end, channel, channel_key_hex_str, iv_hex_str)

    # Create a hash of the subscription struct
    subscription_hash = hashlib.sha256(packed_data).digest()

    # Encrypt the subscription struct
    encrypted_data = encrypt_subscription_struct(master_key_encoder, packed_data + subscription_hash)

    # Verify the encrypted subscription file
    if verify_before_write:
        expected_values = {
            "device_id": device_id,
            "start": start,
            "end": end,
            "channel": channel,
            "channel_key": bytes.fromhex(channel_key_hex_str),
            "iv": bytes.fromhex(iv_hex_str),
            "hash": subscription_hash
        }

        master_key_decoder = master_key_encoder
        verify_encrypted_sub(master_key_decoder, encrypted_data, expected_values)

    # Pack the subscription. This will be sent to the decoder with ectf25.tv.subscribe
    return encrypted_data


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """Main function of gen_subscription

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )

    # Print the generated subscription for your own debugging
    # Attackers will NOT have access to the output of this (although they may have
    # subscriptions in certain scenarios), but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated subscription: {subscription}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")


if __name__ == "__main__":
    main()
