import base64
from typing import List

import numpy as np


def detect_AES_ECB(input: List[bytes]) -> int:
    counts = []
    for input in inputs:
        count = 0
        for i in range(0, len(input), 16):
            substring = input[i : i + 16]
            count += input.count(substring)
        counts.append(count)
    counts = np.array(counts)
    maximum_counts = np.argmax(counts)
    print(f"line {maximum_counts} is probably encrypted with AEC-ECB.")
    return maximum_counts


if __name__ == "__main__":
    inputs = []
    with open("data/challenge_8.txt") as file:
        for line in file:
            inputs.append(base64.b64decode(line.strip()))
    detect_AES_ECB(inputs)
