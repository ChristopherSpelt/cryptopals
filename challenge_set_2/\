import random
import secrets
import sys
from typing import Tuple

sys.path.append("../challenge_set_1/")
from challenge_7 import encrypt_AES_ECB

from challenge_10 import encrypt_AES_CBC


def encryption_oracle(input: bytes) -> bytes:
    key = secrets.token_bytes(16)
    append_len_1 = random.randint(5, 10)
    append_len_2 = random.randint(5, 10)
    append_1 = secrets.token_bytes(append_len_1)
    append_2 = secrets.token_bytes(append_len_2)

    plaintext = append_1 + input + append_2
    encryption_method = random.randint(0, 1)
    print(f"encryption method: {encryption_method}")
    if encryption_method == 0:
        iv = secrets.token_bytes(len(key))
        return encrypt_AES_CBC(plaintext=plaintext, key=key, initialization_vector=iv)
    else:
        return encrypt_AES_ECB(plaintext=plaintext, key=key)


def detect_ECB_encryption_mode(input: bytes, keysize: int) -> bool:

    count = 0
    for i in range(0, len(input), keysize):
        substring = input[i : i + 16]
        count += input.count(substring)

    expected_count = len(input) / keysize
    if count == expected_count:
        return False

    return True


if __name__ == "__main__":
    with open("data/challenge_10_1.txt") as file:
        plaintext = bytes(file.read(), encoding="ascii")

    cyphertext = encryption_oracle(plaintext)
    print(detect_ECB_encryption_mode(cyphertext, 16))
