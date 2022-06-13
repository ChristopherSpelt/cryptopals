import binascii


def encrypt_repeating_key_xor_cypher(input: bytes, key: bytes) -> bytes:
    input_len = len(input)
    key_len = len(key)
    return binascii.hexlify(
        bytes([input[i] ^ key[i % key_len] for i in range(input_len)])
    )


if __name__ == "__main__":
    input = (
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )
    key = b"ICE"
    print(encrypt_repeating_key_xor_cypher(input, key))
