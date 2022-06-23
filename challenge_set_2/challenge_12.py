import base64
import secrets

from challenge_11 import encryption_oracle


def detect_block_size(max: int = 33) -> int:
    random_key = secrets.token_bytes(16)
    mystring = b"A"
    previous_len = 0
    for i in range(0, max):
        cyphertext = encryption_oracle(input=mystring, key=random_key, only_ECB=True)
        print(f'cypher: {len(cyphertext)}')
        current_len = len(cyphertext)
        #print(
        #    f"input size is {len(mystring)} bytes with output of length {len(cyphertext)}"
        #)
        #print('\n')
        #if current_len > previous_len:
        #    return current_len
        previous_len = current_len
        mystring += b"A"


if __name__ == "__main__":
    with open("data/challenge_12.txt") as file:
        unknown_string = base64.b64decode(file.read())

    print(detect_block_size())
