"""Exercise a FRESH disposable Compose deployment; read setup token on stdin.

Creates a temporary admin, loads/removes demo through the GUI and checks state.
Never run this against an already configured or production instance.
"""
import http.cookiejar
import json
import os
import secrets
import ssl
import sys
import time
import urllib.parse
import urllib.request

base = os.getenv("DEEPSNOUT_SMOKE_URL", "https://localhost").rstrip("/")
ca_file = os.getenv("DEEPSNOUT_SMOKE_CA")
tls = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
cookies = http.cookiejar.CookieJar()
http = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=tls),
    urllib.request.HTTPCookieProcessor(cookies),
)


def get(path):
    with http.open(base + path, timeout=10) as response:
        return response.read().decode()


def post(path, data):
    csrf = next(c.value for c in cookies if c.name == "ds_csrf")
    body = urllib.parse.urlencode({"csrf": csrf, **data}).encode()
    with http.open(base + path, body, timeout=10) as response:
        return response.read().decode()


def wait_for(count):
    for _ in range(60):
        state = json.loads(get("/api/status"))
        if state["open_findings"] == count:
            return state
        time.sleep(1)
    raise RuntimeError("Worker did not produce the expected state; inspect Compose logs")


def main():
    setup_token = sys.stdin.read().strip()
    if not setup_token or 'name="setup_token"' not in get("/setup"):
        raise RuntimeError("Requires an unconfigured, disposable deployment and setup token on stdin")
    password = secrets.token_urlsafe(24)
    post("/setup", {"setup_token": setup_token, "username": "ci-admin", "password": password})
    get("/login")
    post("/login", {"username": "ci-admin", "password": password})
    assert json.loads(get("/api/status"))["endpoints"] == 0
    post("/demo", {})
    state = wait_for(2)
    assert state["endpoints"] == 2
    post("/demo/remove", {})
    state = wait_for(0)
    assert state["endpoints"] == 0
    print("Compose HTTPS setup, login, worker analysis and scoped demo removal passed.")


if __name__ == "__main__":
    main()
