"""
Data collection layer (Layer 1).

Collectors are anything that produces raw security events: agents on
endpoints, syslog forwarders, cloud audit-log exporters, etc. Their only
job is to get data in, untouched - no parsing or detection logic belongs
here. That logic lives in detection_engine/processing.py.

store_raw_event() is the single write path every collector should use,
called from the backend's /api/events route after auth has already
been checked.
"""

import json
from datetime import datetime, timezone

from database.db import Database


def store_raw_event(db: Database, source: str, payload: dict) -> int:
    """Persist a raw, unmodified event payload. Returns the new raw_event id."""
    with db.session() as conn:
        cur = conn.execute(
            "INSERT INTO raw_events (source, raw_payload, received_at) VALUES (?, ?, ?)",
            (source, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid
