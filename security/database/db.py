"""
Database layer (Layer 8).

Owns the schema and the connection. Every other layer talks to storage
only through the functions in this file - no other module should open
sqlite3 connections directly. That keeps a future swap to Postgres/
Elasticsearch contained to this one file.
"""

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_event_id INTEGER,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    user TEXT,
    severity TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT,
    ioc_match INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (raw_event_id) REFERENCES raw_events (id)
);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events (user, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events (source_ip, timestamp);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);
"""


class Database:
    """Thin wrapper around a sqlite3 connection for this process."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def init_schema(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def session(self):
        """Usage: with db.session() as conn: conn.execute(...)"""
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
