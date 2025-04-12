import sys
import json
from Crypto.PublicKey import RSA, ECC

master_key_type = "AES"
signature_type = "EdDSA"

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

    decoder_id = str(int(sys.argv[3], base=16))
    with open(sys.argv[2]) as secrets_file:
        secrets = json.load(secrets_file)

    # ----------------------------------
    # Master Key placeholder replacement
    # ----------------------------------
    if master_key_type == "RSA":
        rsa_private_key_pem_str = secrets["decoder_details"][decoder_id]["master_key_decoder"]
        private_key = RSA.import_key(rsa_private_key_pem_str)
        rsa_key_der = private_key.export_key(format='DER')

        update_c_file(sys.argv[1], rsa_key_der, "/*$LEN_RSA_PRIV_KEY$*/", "/*$RSA_PRIV_KEY$*/")

        # To prevent compiler time error
        update_c_file(sys.argv[1], b'', "/*$LEN_AES_KEY$*/", "/*$PLACEHOLDER$*/")

    elif master_key_type == "AES":
        aes_master_key = secrets["decoder_details"][decoder_id]["master_key_decoder"]
        aes_key_der = bytes.fromhex(aes_master_key)
        update_c_file(sys.argv[1], aes_key_der, "/*$LEN_AES_KEY$*/", "/*$AES_KEY$*/")

        # To prevent compile time error
        update_c_file(sys.argv[1], b'', "/*$LEN_RSA_PRIV_KEY$*/", "/*$PLACEHOLDER$*/")

    else:
        ValueError(f"Master Key type {master_key_type} undefined")

    # ----------------------------------
    # Emergency Channel Key replacement
    # ----------------------------------
    # const byte_t emergency_channel_key[CHNL_KEY_LENGTH] /*$EMERGENCY_CHANNEL_KEY$*/
    # const byte_t emergency_channel_iv[INIT_VEC_LENGTH] /*$EMERGENCY_CHANNEL_IV$*/

    channel_key_hex_str = secrets["channel_details"]["0"]["channel_key"]
    channel_key_bytes = bytes.fromhex(channel_key_hex_str)
    update_c_file(sys.argv[1], channel_key_bytes, "/*$EMERGENCY_CHANNEL_KEY_LEN$*/", "/*$EMERGENCY_CHANNEL_KEY$*/")

    channel_iv_hex_str = secrets["channel_details"]["0"]["channel_iv"]
    channel_iv_bytes = bytes.fromhex(channel_iv_hex_str)
    update_c_file(sys.argv[1], channel_iv_bytes, "/*$EMERGENCY_CHANNEL_IV_LEN$*/", "/*$EMERGENCY_CHANNEL_IV$*/")