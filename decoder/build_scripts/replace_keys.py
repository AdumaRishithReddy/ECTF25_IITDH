import sys
import json
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES
import hashlib

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


def bytes_to_c_array(byte_data):
    hex_list = [f"0x{byte:02x}" for byte in byte_data]
    # Create lines with 8 elements each
    lines = []
    for i in range(0, len(hex_list), 8):
        lines.append(", ".join(hex_list[i:i+8]))
    return "= {\n" + ",\n".join(lines) + "\n}"


def update_c_file(file_path, byte_data, len_string_to_replace, key_string_to_replace):
    # Calculate the length of the byte data
    key_length = len(byte_data)

    # Convert the byte data to a C array string
    key_array = bytes_to_c_array(byte_data)

    # Read the original C file
    with open(file_path, 'r') as file:
        content = file.read()

    # Replace the placeholders
    content = content.replace(len_string_to_replace, str(key_length))
    content = content.replace(key_string_to_replace, key_array)

    # Write the modified content back to the C file
    with open(file_path, 'w') as file:
        file.write(content)

if __name__ == "__main__":
    if(len(sys.argv) != 4):
        print(f"Usage: python {sys.argv[0]} <c-file> <secrets-file> <decoder-id>")
        exit(0)

    decoder_id = int(sys.argv[3], base=16)
    with open(sys.argv[2]) as secrets_file:
        secrets = json.load(secrets_file)

    # ----------------------------------
    # Master Key placeholder replacement
    # ----------------------------------

    # Load the random 16 bytes used to create master key
    random_16_bytes = secrets["decoder_details"]["random_16_bytes"]
    if random_16_bytes is None:
        raise ValueError("No Random 16 bytes found")

    random_16_bytes = bytes.fromhex(random_16_bytes)

    # Create the master key for this device
    aes_key = hashlib.pbkdf2_hmac('sha256', random_16_bytes, decoder_id.to_bytes(4,'big'), 1000, dklen=16)

    # Update the C file
    update_c_file(sys.argv[1], aes_key, "/*$LEN_AES_KEY$*/", "/*$AES_KEY$*/")


    # ----------------------------------
    # Emergency Channel Key replacement
    # ----------------------------------

    channel_key_hex_str = secrets["channel_details"]["0"]["channel_key"]
    channel_key_bytes = bytes.fromhex(channel_key_hex_str)
    update_c_file(sys.argv[1], channel_key_bytes, "/*$EMERGENCY_CHANNEL_KEY_LEN$*/", "/*$EMERGENCY_CHANNEL_KEY$*/")

    channel_iv_hex_str = secrets["channel_details"]["0"]["channel_iv"]
    channel_iv_bytes = bytes.fromhex(channel_iv_hex_str)
    update_c_file(sys.argv[1], channel_iv_bytes, "/*$EMERGENCY_CHANNEL_IV_LEN$*/", "/*$EMERGENCY_CHANNEL_IV$*/")