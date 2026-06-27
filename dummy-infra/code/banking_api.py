"""
Intentional vulnerable banking-style API patterns (fixture only — do not deploy).
Semgrep OWASP rules target: SQLi, SSRF, hardcoded secrets, unsafe deserialization.
"""
from __future__ import annotations

import hashlib
import logging
import pickle
import sqlite3
from typing import Any

import requests

logger = logging.getLogger(__name__)

JWT_SECRET = "kb-demo-jwt-secret-do-not-use-in-production"
DB_PASSWORD = "admin1234"


def lookup_account_by_id(account_id: str) -> dict[str, Any]:
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT balance, owner FROM accounts WHERE id = '{account_id}'"
    cursor.execute(query)
    row = cursor.fetchone()
    return {"balance": row[0], "owner": row[1]} if row else {}


def fetch_statement_from_url(statement_url: str) -> str:
    response = requests.get(statement_url, timeout=5)
    return response.text


def verify_transfer_token(token_blob: bytes) -> dict[str, Any]:
    return pickle.loads(token_blob)


def hash_customer_pin(pin: str) -> str:
    return hashlib.md5(pin.encode()).hexdigest()


def log_transfer(account_number: str, amount: float, owner_rrn: str) -> None:
    logger.info("transfer account=%s amount=%s rrn=%s", account_number, amount, owner_rrn)
