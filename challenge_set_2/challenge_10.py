import base64
import sys
from posixpath import split
from pydoc import plain
from typing import List

sys.path.append("../challenge_set_1/")
from challenge_7 import decrypt_AES_ECB, encrypt_AES_ECB

from challenge_9 import pad_block


def xor(x: bytes, y: bytes) -> bytes:
    if len(x) != len(y):
        print(
            f"Error: lengths of input must be equal, but got lengths {len(x)} and {len(y)} "
        )
    return bytes([a ^ b for (a, b) in zip(x, y)])


def split_into_blocks(input: bytes, blocksize: int) -> List[bytes]:
    if blocksize > 256:
        print("Error: cannot exceed maximum blocksize of 256")
        return [""]

    blocks = [input[i : i + blocksize] for i in range(0, len(input), blocksize)]

    if blocks[-1] == blocksize:
        blocks.append(blocksize.to_bytes(1, byteorder="big") * blocksize)
        return blocks

    blocks[-1] = pad_block(blocks[-1], blocksize)
    return blocks


def encrypt_AES_CBC(
    plaintext: bytes, key: bytes, initialization_vector: bytes
) -> bytes:
    block_length = len(key)
    blocks = split_into_blocks(plaintext, block_length)

    blocks[0] = encrypt_AES_ECB(xor(blocks[0], initialization_vector), key)
    for i in range(1, len(blocks)):
        blocks[i] = encrypt_AES_ECB(xor(blocks[i - 1], blocks[i]), key)
    return b"".join(blocks)


def decrypt_AES_CBC(
    cyphertext: bytes, key: bytes, initialization_vector: bytes
) -> bytes:
    block_length = len(key)
    blocks = split_into_blocks(cyphertext, block_length)

    plaintext = [b""] * len(blocks)
    plaintext[0] = xor(decrypt_AES_ECB(blocks[0], key), initialization_vector)
    for i in range(1, len(blocks)):
        plaintext[i] = xor(blocks[i - 1], decrypt_AES_ECB(blocks[i], key))

    return b"".join(plaintext)


if __name__ == "__main__":
    with open("data/challenge_10.txt") as file:
        cyphertext = base64.b64decode(file.read())

    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * len(key)
    plaintext = decrypt_AES_CBC(
        cyphertext=cyphertext, key=key, initialization_vector=iv
    )
    print(plaintext)
