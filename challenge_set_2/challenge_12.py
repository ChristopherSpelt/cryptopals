import base64
import string
import secrets
import sys
from typing import Callable

sys.path.append("../challenge_set_1/")
from challenge_7 import encrypt_AES_ECB

from challenge_11 import detect_ECB_encryption_mode


RANDOM_KEY = secrets.token_bytes(16)
with open("data/challenge_12.txt") as file:
    UNKOWN_STRING = base64.b64decode(file.read())


def ECB_encryption_oracle(mystring: bytes) -> bytes:
    plaintext = mystring + UNKOWN_STRING
    return encrypt_AES_ECB(plaintext=plaintext, key=RANDOM_KEY)


def detect_block_size(oracle: Callable[[bytes], bytes], max: int = 128) -> int:
    mystring = b"A"
    previous_len = len(oracle(mystring))
    for _ in range(1, max):
        cyphertext = oracle(mystring)
        current_len = len(cyphertext)
        if current_len > previous_len:
            return current_len - previous_len
        previous_len = current_len
        mystring += b"A"


def detect_ECB(oracle: Callable[[bytes], bytes], blocksize: int) -> bool:
    mystring = b"A" * 1024
    cyphertext = oracle(mystring)
    return detect_ECB_encryption_mode(cyphertext, blocksize)


def decrypt_ECB_oracle(oracle: Callable[[bytes], bytes], blocksize: int) -> bytes:
    cyphertext = oracle(b"")
    decypted_message = b""
    text_size = len(cyphertext)
    for i in range(text_size, 1, -1):
        mystring = b"A" * (i - 1)
        cyphertext = oracle(mystring)[text_size - blocksize : text_size]
        for char in string.printable:
            teststring = mystring + decypted_message + bytes(char, "ascii")
            out = oracle(teststring)[text_size - blocksize : text_size]
            if out == cyphertext:
                decypted_message += bytes(char, "ascii")
                break
    return decypted_message.decode("ascii")


if __name__ == "__main__":
    blocksize = detect_block_size(ECB_encryption_oracle)
    print(f"blocksize is {blocksize}")
    print(f"oracle using ECB: {detect_ECB(ECB_encryption_oracle, blocksize)}")
    print(f"decrypted text is:\n{decrypt_ECB_oracle(ECB_encryption_oracle, blocksize)}")
