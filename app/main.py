<<<<<<< HEAD
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sqlite3
import time
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
=======
import os
import sqlite3
import uuid
import base64
import hashlib
import time
import json
from collections import deque
from contextlib import closing
from typing import Optional

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel
>>>>>>> ee5af9c (Project 3 submission)

DB_FILE = "totally_not_my_privateKeys.db"

# ---------- DB SETUP ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

<<<<<<< HEAD
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    # check if empty
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        # generate two keys
        now = int(time.time())

        for exp_time in [now - 1000, now + 3600]:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (pem, exp_time)
            )

    conn.commit()
    conn.close()

# ---------- UTILS ----------
def load_key(row):
    return serialization.load_pem_private_key(row[1], password=None)

def rsa_to_jwk(private_key, kid):
    public_numbers = private_key.public_key().public_numbers()

    def b64(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "kid": str(kid),
        "use": "sig",
        "alg": "RS256",
        "n": b64(public_numbers.n),
        "e": b64(public_numbers.e)
    }

# ---------- SERVER ----------
class Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path.startswith("/auth"):
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            now = int(time.time())

            if "expired" in self.path:
                cursor.execute(
                    "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
                    (now,)
                )
            else:
                cursor.execute(
                    "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
                    (now,)
                )

            row = cursor.fetchone()
            conn.close()

            if not row:
                self.send_response(500)
                self.end_headers()
                return

            kid, key_blob, exp = row
            private_key = load_key(row)

            payload = {
                "user": "userABC",
                "exp": exp
            }

            token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(kid)})

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(json.dumps({"token": token}).encode())

        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            now = int(time.time())

            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ?",
                (now,)
            )

            rows = cursor.fetchall()
            conn.close()

            jwks = {"keys": []}

            for row in rows:
                private_key = load_key(row)
                jwks["keys"].append(rsa_to_jwk(private_key, row[0]))

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(json.dumps(jwks).encode())

        else:
            self.send_response(404)
            self.end_headers()

# ---------- MAIN ----------
if __name__ == "__main__":
    init_db()
    server = HTTPServer(("localhost", 8080), Handler)
    print("Server running on http://localhost:8080")
    server.serve_forever()
=======
DB_PATH = "totally_not_my_privateKeys.db"
ACTIVE_KEY_ID = "active"
EXPIRED_KEY_ID = "expired"

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

auth_timestamps = deque()


class RegisterRequest(BaseModel):
    username: str
    email: Optional[str] = None


class AuthRequest(BaseModel):
    username: str


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid TEXT PRIMARY KEY,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL,
                public_jwk TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        conn.commit()


def get_aes_key() -> bytes:
    raw_key = os.getenv("NOT_MY_KEY")
    if not raw_key:
        raise RuntimeError("NOT_MY_KEY environment variable is not set")

    return hashlib.sha256(raw_key.encode()).digest()


def encrypt_private_key(private_pem) -> str:
    key = get_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    if isinstance(private_pem, str):
        private_bytes = private_pem.encode()
    else:
        private_bytes = private_pem

    ciphertext = aesgcm.encrypt(nonce, private_bytes, None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_private_key(encrypted_blob: str):
    key = get_aes_key()
    aesgcm = AESGCM(key)

    raw = base64.b64decode(encrypted_blob.encode())
    nonce = raw[:12]
    ciphertext = raw[12:]

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


def store_key_if_missing(kid: str, expires_at: int):
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()

        cur.execute("SELECT kid FROM keys WHERE kid = ?", (kid,))
        row = cur.fetchone()

        if row is None:
            kp = generate_rsa_keypair(expires_at)
            encrypted_private = encrypt_private_key(kp.private_pem)
            public_jwk_json = json.dumps(kp.public_jwk)

            cur.execute("""
                INSERT INTO keys(kid, key, exp, public_jwk)
                VALUES (?, ?, ?, ?)
            """, (kid, encrypted_private, kp.expires_at, public_jwk_json))

            conn.commit()


def fetch_key(kid: str):
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()

        cur.execute("""
            SELECT kid, key, exp, public_jwk
            FROM keys
            WHERE kid = ?
        """, (kid,))

        return cur.fetchone()


def get_user_by_username(username: str):
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()

        cur.execute("""
            SELECT id, username
            FROM users
            WHERE username = ?
        """, (username,))

        return cur.fetchone()


def log_auth_request(request_ip: str, user_id: Optional[int]):
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO auth_logs(request_ip, user_id)
            VALUES (?, ?)
        """, (request_ip, user_id))

        conn.commit()


def rate_limited() -> bool:
    now = time.time()

    while auth_timestamps and now - auth_timestamps[0] > 1:
        auth_timestamps.popleft()

    if len(auth_timestamps) >= 10:
        return True

    auth_timestamps.append(now)
    return False


@app.on_event("startup")
def startup():
    create_tables()

    now = now_ts()
    store_key_if_missing(ACTIVE_KEY_ID, now + 3600)
    store_key_if_missing(EXPIRED_KEY_ID, now - 3600)


@app.get("/")
def root():
    return {"message": "JWKS Server is running"}


@app.get("/.well-known/jwks.json")
def jwks():
    row = fetch_key(ACTIVE_KEY_ID)

    if row is None:
        return {"keys": []}

    if is_expired(row["exp"]):
        return {"keys": []}

    return {"keys": [json.loads(row["public_jwk"])]}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest):
    generated_password = str(uuid.uuid4())
    password_hash = ph.hash(generated_password)

    try:
        with closing(get_db_connection()) as conn:
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO users(username, password_hash, email)
                VALUES (?, ?, ?)
            """, (payload.username, password_hash, payload.email))

            conn.commit()

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400,
            detail="username or email already exists"
        )

    return {"password": generated_password}


@app.post("/auth")
def auth(
    request: Request,
    payload: AuthRequest,
    expired: Optional[str] = None
):
    if rate_limited():
        raise HTTPException(status_code=429, detail="Too Many Requests")

    use_expired = expired is not None
    kid = EXPIRED_KEY_ID if use_expired else ACTIVE_KEY_ID

    row = fetch_key(kid)

    if row is None:
        raise HTTPException(status_code=500, detail="Key not found")

    private_pem = decrypt_private_key(row["key"])
    private_text = private_pem.decode()

    token_payload = {
        "sub": payload.username,
        "iat": now_ts(),
        "exp": row["exp"],
    }

    token = jwt.encode(
        token_payload,
        private_text,
        algorithm="RS256",
        headers={"kid": row["kid"]},
    )

    user = get_user_by_username(payload.username)
    user_id = user["id"] if user else None

    client_ip = request.client.host if request.client else "unknown"
    log_auth_request(client_ip, user_id)

    return {"token": token}
>>>>>>> ee5af9c (Project 3 submission)
