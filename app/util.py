import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class KeyPair:
    kid: str
    private_pem: bytes
    public_jwk: dict
    expires_at: int


def generate_rsa_keypair(expires_at: int) -> KeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_nums = public_key.public_numbers()
    n = _b64url_uint(pub_nums.n)
    e = _b64url_uint(pub_nums.e)

    thumbprint = hashlib.sha256(
        json.dumps({"e": e, "kty": "RSA", "n": n}, separators=(",", ":"), sort_keys=True).encode()
    ).digest()
    kid = (
        base64.urlsafe_b64encode(thumbprint).decode("ascii").rstrip("=")
        + "."
        + uuid.uuid4().hex[:8]
    )

    public_jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    }
    return KeyPair(kid=kid, private_pem=priv_pem, public_jwk=public_jwk, expires_at=expires_at)


def now_ts() -> int:
    return int(time.time())


def is_expired(expires_at: int, now=None) -> bool:
    if now is None:
        now = now_ts()
    return expires_at <= now
