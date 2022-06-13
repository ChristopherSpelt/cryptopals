import binascii

import numpy as np
from challenge_3 import crack_single_xor_cypher, fitting_quotient

if __name__ == "__main__":
    file = open("data/challenge_4.txt", "r")
    candidates = []
    for line in file:
        input = binascii.unhexlify(line.strip())
        text, _, _ = crack_single_xor_cypher(input, 1)
        if len(text) > 0:
            candidates.append([str(x) for x in text])
    file.close()
    scores = np.array([fitting_quotient(x[0]) for x in candidates])
    best_score_idxs = np.argsort(scores)
    print([candidates[idx][0] for idx in best_score_idxs[:10]])
