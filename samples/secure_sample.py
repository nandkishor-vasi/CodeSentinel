"""Hardened counterparts of the utilities in vulnerable_sample.py.

Secrets come from the environment, queries are parameterised, subprocess is avoided
in favour of pure-Python code, and exceptions are specific and logged.
"""

import ast
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import tempfile
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

PBKDF2_ROUNDS = 600_000
REQUEST_TIMEOUT_SECONDS = 10


def get_db_credential():
    """Return the database credential from the environment."""
    value = os.environ.get("APP_DB_SECRET")
    if not value:
        raise RuntimeError("APP_DB_SECRET is not configured")
    return value


def hash_secret(plain_text, salt=None):
    """Return (salt, digest) using PBKDF2-HMAC-SHA256."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", plain_text.encode(), salt, PBKDF2_ROUNDS)
    return salt, digest


def verify_secret(plain_text, salt, expected):
    """Check a secret against a stored digest in constant time."""
    _, digest = hash_secret(plain_text, salt)
    return hmac.compare_digest(digest, expected)


def new_session_id():
    """Create an unpredictable session identifier."""
    return secrets.token_urlsafe(32)


def parse_literal(expression):
    """Safely parse a Python literal (numbers, strings, lists, dicts)."""
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError) as exc:
        raise ValueError("expression is not a valid literal") from exc


def load_session(blob):
    """Restore a session from JSON instead of pickle."""
    return json.loads(blob)


def find_user(conn: sqlite3.Connection, username):
    """Look up a user with a parameterised query."""
    cursor = conn.execute("SELECT id, name FROM users WHERE name = ?", (username,))
    return cursor.fetchall()


def fetch_remote_data(url):
    """Download data over HTTPS with certificate verification and a timeout."""
    if not url.startswith("https://"):
        raise ValueError("only https URLs are allowed")
    response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.text


def write_export(data):
    """Write an export to a private temporary file and return its path."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(data)
        path = Path(handle.name)
    path.chmod(0o600)
    return path


def cleanup(path):
    """Remove a file, logging failures instead of hiding them."""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        logger.debug("%s was already removed", path)
    except OSError as exc:
        logger.warning("Could not remove %s: %s", path, exc)
        raise


def check_admin(user):
    """Raise unless the user is an administrator."""
    if not user or not user.get("is_admin"):
        raise PermissionError("administrator privileges required")


def item_total(item, region):
    """Price of a single order line including regional tax."""
    rates = {"EU": 1.2, "US": 1.1}
    return item["price"] * item["qty"] * rates.get(region, 1.0)


def process_order(order, region, discount=0):
    """Total an order, applying an optional flat discount."""
    total = sum(item_total(item, region) for item in order["items"])
    return max(total - discount, 0)
