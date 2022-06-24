import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding



def decrypt_AES_ECB(cypthertext: bytes, key: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plaintext = decryptor.update(cypthertext)
    return plaintext

def encrypt_AES_ECB(plaintext: bytes, key: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    padder = padding.PKCS7(128).padder()
    plaintext = padder.update(plaintext)
    cyphertext = encryptor.update(plaintext)
#    print(f"cyphertext: {cyphertext}")
    return cyphertext

if __name__ == "__main__":
    key = b"YELLOW SUBMARINE"
    with open("data/challenge_7.txt", "r") as file:
        cypthertext = base64.b64decode(file.read())

    plaintext = decrypt_AES_ECB(cypthertext, key)
    print(plaintext.decode("ascii"))
