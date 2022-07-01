from typing import Optional


def pkcs7_pad(text: bytes, blocksize: int) -> Optional[bytes]:

    bytes_to_pad = blocksize - (len(text) % blocksize)
    if bytes_to_pad < 0:
        print(
            f"Error: cannot pad text of block size {len(text)} to padded block of size {blocksize}"
        )
        return

    if bytes_to_pad == 0:
        pad_value = len(text).to_bytes(1, byteorder="big")
        bytes_to_pad = len(text)
    else:
        pad_value = bytes_to_pad.to_bytes(1, byteorder="big")

    return text + bytes_to_pad * pad_value


def pkcs7_unpad(text: bytes) -> Optional[bytes]:
    pad_value = text[-1]
    if pad_value > 16 or pad_value <= 0:
        print(f"Error: invalid pad value: {pad_value}")
        return
    padding = text[-pad_value:]
    if set(padding) != {pad_value}:
        print(f"Error: invalid padding: {padding}")
        return
    return text[:-pad_value]


if __name__ == "__main__":
    plaintext = b"YELLOW SUBMARINE"
    padded_text = pkcs7_pad(plaintext, 16)
    print(padded_text)
    print(pkcs7_unpad(padded_text))

    valid_pad = b"ICE ICE BABY\x04\x04\x04\x04"
    invalid_pad_1 = b"ICE ICE BABY\x05\x05\x05\x05"
    invalid_pad_2 = b"ICE ICE BABY\x01\x02\x03\x04"
    invalid_pad_3 = b"ICE ICE BABY\x00"
    invalid_pad_4 = b"ICE ICE BABY"
    print(pkcs7_unpad(valid_pad))
    print(pkcs7_unpad(invalid_pad_1))
    print(pkcs7_unpad(invalid_pad_2))
    print(pkcs7_unpad(invalid_pad_3))
    print(pkcs7_unpad(invalid_pad_4))
