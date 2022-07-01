def pkcs7_pad(text: bytes, blocksize: int) -> bytes:

    bytes_to_pad = blocksize - (len(text) % blocksize)
    if bytes_to_pad < 0:
        print(
            f"Error: cannot pad text of block size {len(text)} to padded block of size {blocksize}"
        )
        return b""

    if bytes_to_pad == 0:
        pad_value = len(text).to_bytes(1, byteorder="big")
        bytes_to_pad = len(text)
    else:
        pad_value = bytes_to_pad.to_bytes(1, byteorder="big")

    return text + bytes_to_pad * pad_value


def pkcs7_unpad(text: bytes) -> bytes:
    return text[: -text[-1]]


if __name__ == "__main__":
    plaintext = b"YELLOW SUBMARINE"
    padded_text = pkcs7_pad(plaintext, 16)
    print(padded_text)
    print(pkcs7_unpad(padded_text))
