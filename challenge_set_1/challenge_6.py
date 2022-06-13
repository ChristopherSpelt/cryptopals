import base64
from itertools import zip_longest
from typing import List

import numpy as np
from challenge_4 import crack_single_xor_cypher


def hamming_distance(x: bytes, y: bytes) -> int:
    if len(x) != len(y):
        print(
            f"Error: input parameters must have same number of bits, but got inputs of size {len(x)}B and {len(y)}B."
        )
        return -1
    bitwise_xor = bytes(a ^ b for (a, b) in zip(x, y))
    bits = np.array(
        list(map(int, list("".join([format(byte, "08b") for byte in bitwise_xor]))))
    )
    return np.count_nonzero(bits)


def get_likely_keysize(cypher_text: bytes, min: int, max: int, k: int) -> List[int]:

    # Get the first 4 chunks of the cyphertext of size keysize.
    chunked_text = [
        (
            cypher_text[:keysize],
            cypher_text[keysize : 2 * keysize],
            cypher_text[2 * keysize : 3 * keysize],
            cypher_text[3 * keysize : 4 * keysize],
        )
        for keysize in range(min, max)
    ]

    # Compute the hamming distance of the first two chunks and second two chuncks and average them.
    avg_norm_hamming_dist = np.array(
        [
            (
                hamming_distance(chunked_text[i][0], chunked_text[i][1]) / (i + min)
                + hamming_distance(chunked_text[i][2], chunked_text[i][3]) / (i + min)
            )
            / 2
            for i in range(0, max - min)
        ]
    )
    return np.argsort(avg_norm_hamming_dist)[:k] + min


def get_possible_decrypts(most_likely_keysizes: List[int], cypher_text: bytes):
    possible_keys = []
    for keysize in most_likely_keysizes:
        chunked_text = split_bytes(cypher_text, keysize)
        transposed_text = [bytes(item) for item in zip_longest(*chunked_text)]

        key = []
        output = {}
        output["keysize"] = keysize
        transposed_decrypted_text = []
        for block in transposed_text:
            text, potential_keys, _ = crack_single_xor_cypher(block, 2)
            key.append(chr(potential_keys[0]))
            transposed_decrypted_text.append(text)
        output["key"] = "".join(key)

        decrypted_text = []
        for i in range(0, len(transposed_decrypted_text[0][0])):
            text = [block[0][i] for block in transposed_decrypted_text]
            decrypted_text.append(map(chr, text))

        plaintext = ""
        for block in decrypted_text:
            plaintext += "".join(block)
        output["plaintext"] = plaintext

        possible_keys.append(output)

    return possible_keys


def split_bytes(input: bytes, n: int, pad_value=b"\x00"):
    chunked_bytes = [input[i : i + n] for i in range(0, len(input), n)]
    while len(chunked_bytes[-1]) != n:
        chunked_bytes[-1] += pad_value
    return chunked_bytes


if __name__ == "__main__":
    file = open("data/challenge_6.txt")
    cypher_text = base64.b64decode(file.read())
    file.close()

    nr_keysizes = 3
    most_likely_keysizes = get_likely_keysize(
        cypher_text, min=10, max=41, k=nr_keysizes
    )
    possible_keys = get_possible_decrypts(
        most_likely_keysizes=most_likely_keysizes,
        cypher_text=cypher_text,
    )

    for key in possible_keys:
        print(key)
        print("\n")
