import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ROUNDS = 260_000
SESSION_TTL_SECONDS = 8 * 60 * 60
PRINCIPALS = {"captain", "wesley", "command"}


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_secret(secret: str, salt: bytes | None = None) -> Dict[str, str | int]:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, PBKDF2_ROUNDS)
    return {"salt": b64e(salt), "hash": b64e(digest), "rounds": PBKDF2_ROUNDS}


def verify_secret(secret: str, record: Dict[str, str | int]) -> bool:
    salt = b64d(str(record["salt"]))
    rounds = int(record.get("rounds", PBKDF2_ROUNDS))
    expected = b64d(str(record["hash"]))
    actual = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, rounds)
    return hmac.compare_digest(actual, expected)


@dataclass(frozen=True)
class Principal:
    name: str
    password_hash: Dict[str, str | int]
    api_token_hash: Dict[str, str | int]


class SecurityContext:
    def __init__(self, config: Dict):
        self.config = config
        self.session_key = b64d(config["session_signing_key"])
        self.message_key = b64d(config["message_encryption_key"])
        if len(self.message_key) != 32:
            raise ValueError("message_encryption_key must decode to 32 bytes")
        self.principals: Dict[str, Principal] = {}
        for name, record in config["principals"].items():
            self.principals[name] = Principal(name, record["password"], record["api_token"])

    def authenticate_password(self, name: str, password: str) -> bool:
        principal = self.principals.get(name)
        return bool(principal and verify_secret(password, principal.password_hash))

    def authenticate_api_token(self, token: str) -> Optional[str]:
        for name, principal in self.principals.items():
            if verify_secret(token, principal.api_token_hash):
                return name
        return None

    def sign_session(self, principal: str, now: int | None = None) -> str:
        if principal not in PRINCIPALS:
            raise ValueError("unknown principal")
        now = int(now or time.time())
        payload = {"sub": principal, "iat": now, "exp": now + SESSION_TTL_SECONDS, "nonce": b64e(os.urandom(8))}
        body = b64e(json.dumps(payload, separators=(",", ":")).encode())
        sig = b64e(hmac.new(self.session_key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify_session(self, token: str, now: int | None = None) -> Optional[str]:
        try:
            body, sig = token.split(".", 1)
        except ValueError:
            return None
        expected = b64e(hmac.new(self.session_key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            payload = json.loads(b64d(body))
        except Exception:
            return None
        now = int(now or time.time())
        if int(payload.get("exp", 0)) < now:
            return None
        sub = payload.get("sub")
        return sub if sub in PRINCIPALS else None

    def encrypt_message(self, plaintext: str) -> tuple[str, str]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.message_key).encrypt(nonce, plaintext.encode(), None)
        return b64e(nonce), b64e(ciphertext)

    def decrypt_message(self, nonce: str, ciphertext: str) -> str:
        raw = AESGCM(self.message_key).decrypt(b64d(nonce), b64d(ciphertext), None)
        return raw.decode()


def generate_plain_secret(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"
