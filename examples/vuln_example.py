"""
vuln_example.py
A realistic-looking Python file with several common vulnerabilities
that mirror the C vulnerabilities in vuln_example.c.
Used to demonstrate locate_vuln.py.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib

LOG_FILE = "/tmp/app.log"

# ------------------------------------------------------------------
# 1. Command injection — mirrors C's system(cmd) vuln
# ------------------------------------------------------------------
def run_report(filename):
    """Generate a report for the given filename."""
    os.system("cat " + filename)           # VULN: unsanitised filename → shell injection


# ------------------------------------------------------------------
# 2. SQL injection — mirrors C's unchecked string concat
# ------------------------------------------------------------------
def get_user(username):
    """Fetch a user record from the database."""
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"  # VULN: SQL injection
    cur.execute(query)
    return cur.fetchall()


# ------------------------------------------------------------------
# 3. Arbitrary code execution via eval — mirrors C's format-string
# ------------------------------------------------------------------
def calculate(expression):
    """Evaluate a user-supplied mathematical expression."""
    return eval(expression)                # VULN: arbitrary code execution


# ------------------------------------------------------------------
# 4. Insecure deserialization — mirrors C's use-after-free (memory corruption)
# ------------------------------------------------------------------
def load_session(session_bytes):
    """Restore a user session from serialized bytes."""
    return pickle.loads(session_bytes)     # VULN: arbitrary object deserialization


# ------------------------------------------------------------------
# 5. Path traversal — mirrors C's integer-overflow / heap mis-allocation
# ------------------------------------------------------------------
def read_file(filename):
    """Read and return the contents of a file in the data directory."""
    path = "/var/app/data/" + filename     # VULN: no normalization, allows ../../../etc/passwd
    with open(path, "r") as f:
        return f.read()


# ------------------------------------------------------------------
# Safe helper — parameterised query (no vulnerability)
# ------------------------------------------------------------------
def safe_get_user(username):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchall()


def log_message(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <username>")
        sys.exit(1)
    username = sys.argv[1]
    print(get_user(username))
    run_report(username)
    log_message(username)
