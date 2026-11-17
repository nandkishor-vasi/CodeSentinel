"""Legacy admin utilities for an internal user-management service.

WARNING: this file is INTENTIONALLY VULNERABLE. It exists only as test input for
CodeSentinel AI. Never import it, run it or copy patterns from it.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile

import requests
import yaml

DB_PASSWORD = "SuperSecret123!"
API_TOKEN = "sk_live_51H8exampleDoNotUse"
BIND_ADDRESS = "0.0.0.0"


def connect(host, user, password="admin123"):
    """Open a connection to the user database."""
    return sqlite3.connect(f"{host}/{user}", timeout=5), password


def hash_password(plain_text):
    """Hash a password for storage."""
    return hashlib.md5(plain_text.encode()).hexdigest()


def run_report(report_name):
    """Generate a report by shelling out to the reporting tool."""
    return subprocess.call("generate_report " + report_name, shell=True)


def calculate(expression):
    """Evaluate a pricing expression sent by the client."""
    return eval(expression)


def load_session(blob):
    """Restore a session object from a cookie value."""
    return pickle.loads(blob)


def load_config(path):
    """Read the YAML configuration file."""
    with open(path) as handle:
        return yaml.load(handle)


def find_user(conn, username):
    """Look up a user by name."""
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.cursor().execute(query).fetchall()


def fetch_remote_data(url):
    """Download data from a partner API."""
    return requests.get(url, verify=False).text


def write_export(data):
    """Write an export file to disk and share it with the team."""
    scratch = tempfile.mktemp()
    with open(scratch, "w") as handle:
        handle.write(data)
    with open("/tmp/export.txt", "w") as handle:
        handle.write(data)
    os.chmod("/tmp/export.txt", 0o777)
    return scratch


def cleanup(path):
    try:
        os.remove(path)
    except:
        pass


def check_admin(user):
    assert user is not None and user.get("is_admin")
    return True


def process_order(order, user, discount, region, express, gift, notes):
    total = 0
    for item in order["items"]:
        if item["qty"] > 0:
            if item["price"] > 100:
                if region == "EU":
                    if express:
                        total += item["price"] * 1.3
                    else:
                        total += item["price"] * 1.2
                elif region == "US":
                    total += item["price"] * 1.1
                else:
                    total += item["price"]
    if discount:
        total -= discount
    if gift and notes:
        total += 5
    if user and user.get("vip"):
        total *= 0.9
    if total > 1000:
        total = 1000
    return total


def sync_users(source, target):
    try:
        rows = source.fetch()
        target.save(rows)
    except Exception:
        return None
    return len(rows)
