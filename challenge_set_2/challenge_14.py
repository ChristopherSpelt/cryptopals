import base64
import secrets
import sys
from random import randint

sys.path.append("../challenge_set_1/")
from challenge_7 import encrypt_AES_ECB

from challenge_11 import detect_ECB_encryption_mode


RANDOM_KEY = secrets.token_bytes(16)
with open("data/challenge_12.txt") as file:
    UNKOWN_STRING = base64.b64decode(file.read())


def ECB_encryption_oracle(mystring: bytes) -> bytes:
    prefix_len = randint(0, 16)
    prefix = secrets.token_bytes(prefix_len)
    plaintext = prefix + mystring + UNKOWN_STRING
    return encrypt_AES_ECB(plaintext=plaintext, key=RANDOM_KEY)


if __name__ == "__main__":
    pass
