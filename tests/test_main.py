import os
import threading
import time
import json
import urllib.request
import urllib.error

import app.main as server


def start_server():
    server.init_db()
    httpd = server.HTTPServer(("localhost", 8081), server.Handler)
    httpd.serve_forever()


def request(method, url):
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode()


def test_db_file_created():
    server.init_db()
    assert os.path.exists("totally_not_my_privateKeys.db")


def test_jwks_returns_keys():
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    time.sleep(1)

    status, body = request("GET", "http://localhost:8081/.well-known/jwks.json")
    data = json.loads(body)

    assert status == 200
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1


def test_auth_returns_token():
    status, body = request("POST", "http://localhost:8081/auth")
    data = json.loads(body)

    assert status == 200
    assert "token" in data


def test_auth_expired_returns_token():
    status, body = request("POST", "http://localhost:8081/auth?expired=1")
    data = json.loads(body)

    assert status == 200
    assert "token" in data


def test_invalid_method():
    req = urllib.request.Request("http://localhost:8081/auth", method="GET")
    try:
        urllib.request.urlopen(req)
        assert False
    except urllib.error.HTTPError as e:
        assert e.code in (404, 405)