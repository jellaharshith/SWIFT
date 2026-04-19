"""Intentionally vulnerable Python app — used by SWIFT E2E tests.

This file contains 4 known vulnerabilities that SWIFT should detect:
1. SQL injection (line ~20)
2. Command injection (line ~30)
3. Hardcoded secret (line ~40)
4. Unsafe deserialization (line ~50)
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess


DATABASE = "users.db"


# Vuln 1: SQL Injection — user input concatenated into query
def get_user(user_id: str) -> dict:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id={user_id}"  # VULN: SQL injection
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return {"id": row[0], "name": row[1]} if row else {}


# Vuln 2: Command Injection — user input passed to shell
def run_report(filename: str) -> str:
    output = subprocess.run(f"cat {filename}", shell=True, capture_output=True)  # VULN: command injection
    return output.stdout.decode()


# Vuln 3: Hardcoded Secret — API key in source
API_KEY = "sk-prod-hardcoded-secret-do-not-commit-1234567890"  # VULN: hardcoded secret
ADMIN_PASSWORD = "super_secret_admin_pass_123"  # VULN: hardcoded password


# Vuln 4: Unsafe Deserialization — pickle.loads on untrusted data
def load_session(session_data: bytes) -> dict:
    return pickle.loads(session_data)  # VULN: unsafe deserialization


# Clean function — should NOT be flagged
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# Clean function — safe parameterized query
def get_user_safe(user_id: int) -> dict:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return {"id": row[0], "name": row[1]} if row else {}
