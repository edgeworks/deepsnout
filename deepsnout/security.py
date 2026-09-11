"""Server-side sessions, signed CSRF tokens and secret encryption."""
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import time
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from cryptography.fernet import Fernet

PASSWORDS = PasswordHasher()


def create_secret(path: Path, value: str):
    if path.is_file():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "w") as file:
        file.write(value)


def initialize_secrets(directory):
    create_secret(directory / "app_key", Fernet.generate_key().decode())
    create_secret(directory / "setup_token", secrets.token_urlsafe(32))
    create_secret(directory / "db_password", secrets.token_urlsafe(36))


def crypto(config):
    return Fernet((config.data_dir / "app_key").read_bytes().strip())


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def check_password(stored, password):
    try:
        return PASSWORDS.verify(stored, password)
    except (InvalidHashError, VerifyMismatchError, VerificationError):
        return False


def validate_password(password):
    if not 12 <= len(password) <= 256:
        raise ValueError("Use a password or passphrase between 12 and 256 characters")


def csrf_token(config):
    nonce = secrets.token_urlsafe(24) + "." + str(int(time.time()))
    signature = hmac.new((config.data_dir / "app_key").read_bytes(), nonce.encode(), "sha256").hexdigest()
    return nonce + "." + signature


def check_csrf(config, cookie, supplied):
    if not cookie or not supplied or not hmac.compare_digest(cookie.encode(), supplied.encode()):
        return False
    try:
        nonce, timestamp, signature = cookie.split(".")
        expected = hmac.new((config.data_dir / "app_key").read_bytes(),
                            (nonce + "." + timestamp).encode(), "sha256").hexdigest()
        age = time.time() - int(timestamp)
        return 0 <= age <= 86400 and hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False
