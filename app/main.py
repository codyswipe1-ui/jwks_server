from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sqlite3
import time
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

DB_FILE = "totally_not_my_privateKeys.db"

# ---------- DB SETUP ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

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