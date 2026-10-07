"""
Pipeline orchestration - ties layers 2 through 6 together for one event.

The backend API calls run_pipeline() once per incoming event. Keeping
this orchestration separate from the Flask route means it can be unit
tested without spinning up the web server, and reused by a queue
consumer later if ingestion moves off the request/response path.
"""

from database.db import Database
from detection_engine.processing import normalize_event
from detection_engine.threat_intel import check_threat_intel
from detection_engine.detection import run_detections
from detection_engine.correlation import correlate
from detection_engine.risk import score_incident, save_incident


def run_pipeline(db: Database, raw_event_id: int, raw_payload: dict) -> dict:
    event = normalize_event(raw_payload)
    ioc_match = check_threat_intel(event)

    with db.session() as conn:
        cur = conn.execute(
            """INSERT INTO events
               (raw_event_id, event_type, source_ip, dest_ip, user, severity, timestamp, details, ioc_match)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                raw_event_id, event["event_type"], event["source_ip"], event["dest_ip"],
                event["user"], event["severity"], event["timestamp"], event["details"], ioc_match,
            ),
        )
        event_id = cur.lastrowid

        triggered_rules = run_detections(conn, event, ioc_match)
        incident = correlate(conn, event_id, event, triggered_rules)

        if incident:
            score, level = score_incident(triggered_rules, len(incident["event_ids"]))
            save_incident(conn, incident["rules"], incident["event_ids"], score, level)
            return {
                "event_id": event_id,
                "alerts": triggered_rules,
                "incident_created": True,
                "risk_score": score,
                "risk_level": level,
            }

        return {"event_id": event_id, "alerts": triggered_rules, "incident_created": False}
