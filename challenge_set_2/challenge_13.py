from __future__ import annotations
import re
from typing import Dict, Optional
from uuid import uuid1, UUID


class user_profile:
    def __init__(
        self, email: str, uid: Optional[UUID] = None, role: Optional[str] = None
    ):
        self.email = self._sanitize_email(email)
        self.uid = uid if uid is not None else uuid1()
        self.role = role if role is not None else "user"

    @classmethod
    def from_cyphertext(cls, cyphertext: bytes) -> user_profile:
        name = ""
        uid = ""
        role = ""
        return user_profile(name, uid, role)

    def _sanitize_email(self, email: str) -> str:
        search_string = "(=)+|(&)+"
        return re.sub(search_string, "_", email)

    def encode(self) -> str:
        return f"email={self.email}&uid={self.uid}&role={self.role}"

    def encrypt(self, key: bytes) -> bytes:
        pass

    def __repr__(self):
        return f"\u007b'email': '{self.email}', 'uid': '{self.uid}', 'role': '{self.role}'\u007d"

    @staticmethod
    def parser(input: str) -> Dict:
        search_string = "([A-Za-z0-9_]+)=([A-Za-z0-9_]+)"
        m = re.findall(search_string, input)
        return dict(m)


if __name__ == "__main__":
    test_input = "foo=bar&baz=qux&zap=zazzle"
    print(user_profile.parser(test_input))
