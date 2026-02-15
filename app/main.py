from fastapi import FastAPI
from fastapi.responses import JSONResponse
import jwt

from .util import generate_rsa_keypair, is_expired, now_ts

app = FastAPI()

ACTIVE_KEY = None
EXPIRED_KEY = None

@app.on_event("startup")
def startup():
    global ACTIVE_KEY, EXPIRED_KEY
    now = now_ts()
    ACTIVE_KEY = generate_rsa_keypair(now + 3600)
    EXPIRED_KEY = generate_rsa_keypair(now - 3600)

@app.get("/.well-known/jwks.json")
def jwks():
    keys = []
    if not is_expired(ACTIVE_KEY.expires_at):
        keys.append(ACTIVE_KEY.public_jwk)
    return {"keys": keys}

@app.post("/auth")
def auth(expired=None):
    use_expired = expired is not None
    kp = EXPIRED_KEY if use_expired else ACTIVE_KEY

    payload = {
        "sub": "fake-user",
        "iat": now_ts(),
        "exp": kp.expires_at,
    }

    token = jwt.encode(
        payload,
        kp.private_pem,
        algorithm="RS256",
        headers={"kid": kp.kid},
    )

    return JSONResponse(content={"token": token})
