def pad_block(block: bytes, pad_to: int) -> bytes:
    if pad_to > 256:
        print("Error: cannot pad more than 256 bytes")
        return b""

    bytes_to_pad = pad_to - len(block)
    if bytes_to_pad < 0:
        print(
            f"Error: cannot pad block of block size {len(block)} to padded block of size {pad_to}"
        )
        return b""

    pad_value = bytes_to_pad.to_bytes(1, byteorder="big")
    for _ in range(bytes_to_pad):
        block += pad_value
    return block


if __name__ == "__main__":
    plaintext = b"YELLOW SUBMARINE"

    print(pad_block(plaintext, 20))
