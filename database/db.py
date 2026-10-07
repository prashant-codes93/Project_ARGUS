"""
Database layer (Layer 8).

Owns the schema and the connection. Every other layer talks to storage
only through the functions in this file - no other module should open
sqlite3 connections directly. That keeps a future swap to Postgres/
Elasticsearch contained to this one file.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone


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

CREATE INDEX IF NOT EXISTS idx_events_user_ts
ON events (user, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_ip_ts
ON events (source_ip, timestamp);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    total_events INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0
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

            # =================================================
            # EVENTS MIGRATION
            # Add scan_id if it does not already exist.
            # =================================================

            event_columns = [
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(events)"
                )
            ]

            if "scan_id" not in event_columns:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN scan_id INTEGER"
                )

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_scan_id "
                "ON events (scan_id)"
            )

            # =================================================
            # INCIDENTS MIGRATION
            # Add user_id if it does not already exist.
            # =================================================

            incident_columns = [
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(incidents)"
                )
            ]

            if "user_id" not in incident_columns:
                conn.execute(
                    "ALTER TABLE incidents ADD COLUMN user_id INTEGER"
                )

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_user_id "
                "ON incidents (user_id)"
            )

            # =================================================
            # SCAN SESSIONS MIGRATION
            # Add user_id if it does not already exist.
            # =================================================

            scan_columns = [
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(scan_sessions)"
                )
            ]

            if "user_id" not in scan_columns:
                conn.execute(
                    "ALTER TABLE scan_sessions ADD COLUMN user_id INTEGER"
                )

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_sessions_user_id "
                "ON scan_sessions (user_id)"
            )

            # =================================================
            # SAVE DATABASE CHANGES
            # =================================================

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


# =========================================================
# RAW EVENT STORAGE
# =========================================================

def store_raw_event(
    db: Database,
    source: str,
    payload: dict
) -> int:
    """
    Store the original event payload in raw_events.

    Returns:
        int: ID of the newly stored raw event.
    """

    import json

    with db.session() as conn:

        cursor = conn.execute(
            """
            INSERT INTO raw_events
            (
                source,
                raw_payload,
                received_at
            )
            VALUES (?, ?, ?)
            """,
            (
                source,
                json.dumps(payload),
                datetime.now(timezone.utc).isoformat()
            )
        )

        return cursor.lastrowid