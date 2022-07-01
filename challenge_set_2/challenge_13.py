from __future__ import annotations
import sys
import secrets
import re
from typing import Dict, Optional
from uuid import uuid1, UUID

sys.path.append("../challenge_set_1/")
from challenge_7 import encrypt_AES_ECB, decrypt_AES_ECB

KEY = secrets.token_bytes(16)


class user_profile:
    def __init__(
        self, email: str, uid: Optional[UUID] = None, role: Optional[str] = None
    ):
        self.email = self._sanitize_email(email)
        self.uid = uid if uid is not None else uuid1()
        self.role = role if role is not None else "user"

    # Constructer from encoded user profile
    @classmethod
    def parse(cls, input: str) -> Optional[user_profile]:
        profile = user_profile.parser(input)
        if profile.keys() != {"email", "uid", "role"}:
            print(
                f"Error: invalid keys {[key for key in profile.keys()]} in dictionary, valid keys are ['email', 'uid', 'role'] and must all be present."
            )
            return
        return user_profile(
            email=profile["email"], uid=profile["uid"], role=profile["role"]
        )

    # Constructer from encrypted profile
    @classmethod
    def from_cyphertext(cls, cyphertext: bytes, key: bytes) -> Optional[user_profile]:
        profile = decrypt_AES_ECB(cyphertext, key).decode("ascii")
        return user_profile.parse(profile)

    @staticmethod
    def parser(input: str) -> Dict:
        search_string = "([A-Za-z0-9_\-@\.]+)=([A-Za-z0-9_\-@\.]+)"
        m = re.findall(search_string, input)
        return dict(m)

    def _sanitize_email(self, email: str) -> str:
        search_string = "(=)+|(&)+"
        return re.sub(search_string, "_", email)

    def encode(self) -> str:
        return f"email={self.email}&uid={self.uid}&role={self.role}"

    def encrypt(self, key: bytes) -> bytes:
        return encrypt_AES_ECB(bytes(self.encode(), "ascii"), key)

    def __repr__(self):
        return f"\u007b'email': '{self.email}', 'uid': '{self.uid}', 'role': '{self.role}'\u007d"


if __name__ == "__main__":
    block_size = 16
    profile = user_profile("A" * 11)
    encoded_profile = profile.encode()
    plaintext_len = len(encoded_profile)
    padding_len = (
        block_size - plaintext_len % len(KEY)
        if plaintext_len % len(KEY) != 0
        else len(KEY)
    )

    cyphertext = profile.encrypt(KEY)

    ## This is the encrypted block beginning with "user" and then padding.
    print(cyphertext[-16:])

    ## Now we construct a custom string such that the second block is the same as the last block of cyphertext, that is the print above.
    mystring = (
        (block_size - len("email=")) * b"A"
        + b"user"
        + padding_len.to_bytes(1, byteorder="big") * padding_len
    )
    profile = user_profile(mystring.decode("ascii"))
    myencode = profile.encode()
    mycyphertext = profile.encrypt(KEY)

    ## This should indeed match the last block of cyphertext
    print(mycyphertext[16:32])
    print("MATCH" if mycyphertext[16:32] == cyphertext[-16:] else "NO MATCH")

    ## Now we simply change "user" to "admin" to and encrypt this to get the cyphertext block containing admin
    mystring = (
        (block_size - len("email=")) * b"A"
        + b"admin"
        + (padding_len - 1).to_bytes(1, byteorder="big") * (padding_len - 1)
    )
    profile = user_profile(mystring.decode("ascii"))
    mycyphertext = profile.encrypt(KEY)[16:32]

    # This now is the cyphertext containing "user" and then padding.
    print(mycyphertext)

    # Now we create our custom user by creating a payload consting of our original cyphertext only with the last block replaced with our admin block.
    payload = cyphertext[0:-16] + mycyphertext
    admin_profile = user_profile.from_cyphertext(payload, key=KEY)
    print(admin_profile)
