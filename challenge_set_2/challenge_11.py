import random
import secrets
import sys

sys.path.append("../challenge_set_1/")
from challenge_7 import encrypt_AES_ECB

from challenge_10 import encrypt_AES_CBC


def encryption_oracle(input: bytes) -> bytes:
    key = secrets.token_bytes(16)
    prefix_len = random.randint(5, 10)
    suffix_len = random.randint(5, 10)
    prefix = secrets.token_bytes(prefix_len)
    suffix = secrets.token_bytes(suffix_len)
    input = prefix + input + suffix

    encryption_method = random.randint(0, 1)
    if encryption_method == 0:
        iv = secrets.token_bytes(len(key))
        return encrypt_AES_CBC(plaintext=input, key=key, initialization_vector=iv)
    else:
        return encrypt_AES_ECB(plaintext=input, key=key)


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
    print(
        "ECB detected"
        if detect_ECB_encryption_mode(cyphertext, 16)
        else "ECB not detected"
    )
