"""
Database helpers for TRACE X.

Every request gets one SQLite connection (stored on Flask's `g` object) that
is closed automatically when the request ends.
"""

import os
import sqlite3
from datetime import datetime

from flask import current_app, g, has_request_context, request

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def now_str():
    """Current local time as 'YYYY-MM-DD HH:MM:SS' (the format used everywhere)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect(path):
    """Open a SQLite connection with foreign keys enforced and dict-like rows."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def create_schema(conn):
    with open(SCHEMA_PATH, encoding="utf-8") as schema_file:
        conn.executescript(schema_file.read())
    conn.commit()


# ---------------------------------------------------------------------------
# Small query helpers. Always pass values through `params` (the ? markers),
# never by building SQL strings from user input. This prevents SQL injection.
# ---------------------------------------------------------------------------

def query_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def query_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def execute(sql, params=(), commit=True):
    """Run an INSERT/UPDATE/DELETE and return the new row id (for inserts)."""
    db = get_db()
    cursor = db.execute(sql, params)
    if commit:
        db.commit()
    return cursor.lastrowid


def placeholders(values):
    """Return '?, ?, ?' for use in an SQL IN (...) clause."""
    return ", ".join("?" for _ in values)


def log_activity(user_id, action, target_type=None, target_id=None, details=None):
    """Write one row to the activity log.

    Never pass passwords, password hashes or API keys in `details`.
    """
    ip_address = request.remote_addr if has_request_context() else None
    execute(
        "INSERT INTO activity_logs (user_id, action, target_type, target_id, details, ip_address, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, action, target_type, None if target_id is None else str(target_id),
         details, ip_address, now_str()),
    )
