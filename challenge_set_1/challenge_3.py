import binascii
from collections import Counter
from typing import List, Tuple, Optional
from challenge_2 import xor

import numpy as np

english_letter_freqs = {
    "E": 0.13,
    "T": 0.091,
    "A": 0.082,
    "O": 0.075,
    "I": 0.07,
    "N": 0.067,
    "S": 0.063,
    "H": 0.061,
    "R": 0.06,
    "D": 0.043,
    "L": 0.04,
    "U": 0.028,
    "C": 0.028,
    "M": 0.024,
    "W": 0.024,
    "F": 0.022,
    "G": 0.02,
    "Y": 0.02,
    "P": 0.019,
    "B": 0.015,
    "V": 0.0098,
    "K": 0.0077,
    "X": 0.0015,
    "J": 0.0015,
    "Q": 0.00095,
    "Z": 0.00074,
}


def decode_singe_xor_cypher(input: bytes, key: int) -> bytes:
    return bytes([byte ^ key for byte in input])


def fitting_quotient(text: str) -> np.float32:
    score: np.float32 = 0.0
    observed_letter_counts = Counter(text.upper())
    for letter in english_letter_freqs:
        observed_letter_freq = observed_letter_counts.get(letter, 0)
        theoretical_letter_freq = english_letter_freqs[letter] * len(text)
        score += (
            np.square(observed_letter_freq - theoretical_letter_freq)
            / theoretical_letter_freq
        )
    return score


def crack_single_xor_cypher(
    input: bytes, k: int
) -> Tuple[List[str], np.ndarray, np.ndarray]:
    outputs = []
    keys = []
    key_scores = []
    for key in range(0, 256):
        output = decode_singe_xor_cypher(input, key)
        if output.isascii():
            outputs.append(output)
            keys.append(key)
            key_scores.append(fitting_quotient(str(output)))

    key_scores = np.array(key_scores)
    keys = np.array(keys)
    best_keys = np.argsort(key_scores)[:k]
    return ([outputs[idx] for idx in best_keys], keys[best_keys], key_scores[best_keys])


if __name__ == "__main__":
    input = binascii.unhexlify(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    outputs, best_keys, key_scores = crack_single_xor_cypher(input, 10)
    for i in range(len(outputs)):
        print(
            f"key {best_keys[i]} with score {key_scores[i]:.{3}f} gives decryption:\n {outputs[i]}\n"
        )
