import numpy as np


def xor(x: bytes, y: bytes) -> bytes:
    x = np.frombuffer(x, dtype="uint8")
    y = np.frombuffer(y, dtype="uint8")
    return np.bitwise_xor(x, y).tobytes()


if __name__ == "__main__":
    x = b"1c0111001f010100061a024b53535009181c"
    y = b"686974207468652062756c6c277320657965"
    print(xor(x, y))
