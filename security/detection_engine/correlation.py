"""
Correlation engine (Layer 5).

When a rule fires, pull in other recent events from the same user or IP
so related activity becomes a single incident instead of a pile of
separate alerts. The 30-minute window is a starting point - the dev
team should tune this per event type once real traffic volume is known.
"""

from datetime import datetime, timedelta

CORRELATION_WINDOW_MIN = 30


def correlate(conn, event_id: int, event: dict, triggered_rules: list[dict]) -> dict | None:
    if not triggered_rules:
        return None

    window_start = (
        datetime.fromisoformat(event["timestamp"]) - timedelta(minutes=CORRELATION_WINDOW_MIN)
    ).isoformat()

    related = conn.execute(
        """SELECT id FROM events
           WHERE (user = ? OR source_ip = ?) AND timestamp >= ?""",
        (event["user"], event["source_ip"], window_start),
    ).fetchall()
    related_ids = sorted({r["id"] for r in related} | {event_id})

    return {
        "event_ids": related_ids,
        "rules": [r["rule"] for r in triggered_rules],
    }
