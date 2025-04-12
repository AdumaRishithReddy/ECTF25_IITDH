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

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from loguru import logger

master_key_type = "AES"
verify_before_write = False

# TODO: Remove this
def print_as_int(label: str, data: bytes):
    out_str = label
    for i in range(0, 13, 4):
        part_int = int.from_bytes(data[i:i+4],  byteorder='little', signed=True)
        out_str += ' ' + str(part_int)

    print(out_str)

def load_keys(secrets, device_id_str, channel_str):
    """Load the master key, channel key, and initialization vector (IV) from the secrets.

    :param secrets: Dictionary containing channel and decoder details.
    :param device_id_str: String representation of the device ID.
    :param channel_str: String representation of the channel.
    :return: Tuple containing the master key encoder, channel key, and IV.
    :raises ValueError: If the master key, channel key, or IV is not found.
    """

    # Load channel and decoder details
    channel_details = secrets["channel_details"]
    decoder_details = secrets["decoder_details"]

    # Load the private encoder master key
    master_key_str = decoder_details[device_id_str]["master_key_encoder"]
    if master_key_str is None:
        raise ValueError("No Master key found for device")

    if master_key_type == "RSA":
        master_key_encoder = RSA.import_key(master_key_str)
    elif master_key_type == "AES":
        master_key_encoder = bytes.fromhex(master_key_str)
    else:
        raise ValueError(f"Master Key type {master_key_type} undefined")

    # Load channel key
    channel_key_hex_str = channel_details[channel_str]["channel_key"]
    if channel_key_hex_str is None:
        raise ValueError("No key found for channel")

    # Load the IV
    iv_hex_str = channel_details[channel_str]["channel_iv"]
    if iv_hex_str is None:
        raise ValueError("No IV found for channel")

    return master_key_encoder, channel_key_hex_str, iv_hex_str

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
    if master_key_type == "RSA":
        cipher = PKCS1_v1_5.new(master_key_encoder)
        return cipher.encrypt(packed_data)

    if master_key_type == "AES":
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
    if master_key_type == "RSA":
        master_key_decoder = RSA.import_key(master_key_decoder)
        cipher_decoder = PKCS1_v1_5.new(master_key_decoder)
        sentinel = b'Error'
        decrypted_data = cipher_decoder.decrypt(encrypted_data, sentinel)

        if decrypted_data == sentinel:
            raise Exception("Padding Error in RSA")

    elif master_key_type == "AES":
        cipher_decoder = AES.new(bytes.fromhex(master_key_decoder), AES.MODE_ECB)
        decrypted_data = cipher_decoder.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_data, AES.block_size)

    unpacked_data = struct.unpack(f"<IQQI16s16s", decrypted_data)

    # Verify each value
    for key, expected_value in expected_values.items():
        actual_value = unpacked_data[["device_id", "start", "end",
                                      "channel", "channel_key", "iv"].index(key)]
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
    master_key_encoder, channel_key_hex_str, iv_hex_str = load_keys(secrets, device_id_str, channel_str)

    # Create the subscription struct
    packed_data = create_subscription_struct(device_id, start, end, channel, channel_key_hex_str, iv_hex_str)

    # Encrypt the subscription struct
    encrypted_data = encrypt_subscription_struct(master_key_encoder, packed_data)

    # Verify the encrypted subscription file
    if verify_before_write:
        expected_values = {
            "device_id": device_id,
            "start": start,
            "end": end,
            "channel": channel,
            "channel_key": bytes.fromhex(channel_key_hex_str),
            "iv": bytes.fromhex(iv_hex_str),
        }

        master_key_decoder = secrets["decoder_details"][device_id_str]["master_key_decoder"]
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
