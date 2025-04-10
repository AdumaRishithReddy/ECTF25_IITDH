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
import json
import os
from pathlib import Path
from Crypto.PublicKey import ECC, RSA
import base64

from loguru import logger

master_key_type = "AES"
signature_type = "EdDSA"

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """

    # List of valid decoder IDs
    dec_ids = [
        0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0x8BADF00D,
        0xC0FFEE00, 0xBAADF00D, 0xF00DBABE, 0xDEADFA11,
        0xB16B00B5, 0xBADC0DE0
    ]

    # Create the Frame signing and Verification keys
    if signature_type == "ECC":
        key = ECC.generate(curve='P-256')
        signing_key = key.export_key(format='PEM')
        verification_key = key.public_key().export_key(format='PEM')
    elif signature_type == "EdDSA":
        key = ECC.generate(curve='ed25519')
        signing_key = key.export_key(format='PEM')
        verification_key = key.public_key().export_key(format='PEM')
    else:
        ValueError(f"Signature type {signature_type} undefined")

    master_keys_list = {}

    # Generate master keys for each decoder
    for dec_id in dec_ids:
        if master_key_type == "RSA":
            m_keys = RSA.generate(2048)
            master_key_decoder = m_keys.export_key().decode('utf-8')
            master_key_encoder = m_keys.public_key().export_key().decode('utf-8')
        elif master_key_type == "AES":
            master_key_decoder = os.urandom(16).hex()
            master_key_encoder = master_key_decoder
        else:
            ValueError(f"Master Key type {master_key_type} undefined")

        master_keys_list[dec_id] = (master_key_decoder, master_key_encoder)

    secrets = {
        "channel_details": {
            cnum: {
                "channel_no": cnum,
                "channel_key": os.urandom(16).hex(),
                "init_vector": os.urandom(16).hex(),
            }
            for cnum in channels + [0]
        },
        "decoder_details": {
            d_id : {
                "decoder_id": d_id,
                "master_key_decoder": master_keys_list[d_id][0],
                "master_key_encoder": master_keys_list[d_id][1],
            }
            for d_id in dec_ids
        },
        "signing_key": signing_key,
        "verification_key": verification_key,
    }

    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
