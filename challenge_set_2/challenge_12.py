import base64
import string
import secrets

from challenge_11 import encryption_oracle, detect_ECB_encryption_mode

RANDOM_KEY = secrets.token_bytes(16)


def detect_block_size(max: int = 128) -> int:
    mystring = b"A"

    previous_len = len(ECB_encryption_oracle(mystring))
    for _ in range(1, max):
        cyphertext = ECB_encryption_oracle(mystring)
        current_len = len(cyphertext)
        if current_len > previous_len:
            return current_len - previous_len
        previous_len = current_len
        mystring += b"A"


def detect_ECB(blocksize: int) -> bool:
    mystring = b"A" * 1024
    cyphertext = ECB_encryption_oracle(mystring)
    return detect_ECB_encryption_mode(cyphertext, blocksize)


def ECB_encryption_oracle(mystring: bytes) -> bytes:
    with open("data/challenge_12.txt") as file:
        unknown_string = base64.b64decode(file.read())
    plaintext = mystring + unknown_string
    return encryption_oracle(input=plaintext, key=RANDOM_KEY, only_ECB=True)


if __name__ == "__main__":
    blocksize = detect_block_size()
    print(f"blocksize is {blocksize}")
    print(f"oracle using ECB: {detect_ECB(blocksize)}\n")

    cyphertext = ECB_encryption_oracle(b"")
    decypted_message = b""
    text_size = len(cyphertext)
    for i in range(text_size, 1, -1):
        mystring = b"A" * (i - 1)
        cyphertext = ECB_encryption_oracle(mystring)[text_size - blocksize : text_size]
        for char in string.printable:
            teststring = mystring + decypted_message + bytes(char, "ascii")
            out = ECB_encryption_oracle(teststring)[text_size - blocksize : text_size]
            if out == cyphertext:
                decypted_message += bytes(char, "ascii")
                break
    print(decypted_message)
