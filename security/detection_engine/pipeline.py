"""
Argus Detection Pipeline

Connects:
1. Event normalization
2. Threat intelligence
3. Detection rules
4. Event correlation
5. Risk scoring
6. Incident creation

The pipeline also attaches every event to the
authenticated user's scan so dashboard data
remains user-specific.
"""

from database.db import Database

from detection_engine.processing import normalize_event
from detection_engine.threat_intel import check_threat_intel
from detection_engine.detection import run_detections
from detection_engine.correlation import correlate
from detection_engine.risk import score_incident, save_incident


def run_pipeline(
    db: Database,
    raw_event_id: int,
    raw_payload: dict,
    scan_id: int | None = None,
    user_id: int | None = None,
) -> dict:

    # ---------------------------------------------------------
    # 1. NORMALIZE EVENT
    # ---------------------------------------------------------

    event = normalize_event(raw_payload)


    # ---------------------------------------------------------
    # 2. THREAT INTELLIGENCE
    # ---------------------------------------------------------

    ioc_match = check_threat_intel(event)


    # ---------------------------------------------------------
    # 3. DATABASE TRANSACTION
    # ---------------------------------------------------------

    with db.session() as conn:

        # -----------------------------------------------------
        # Store normalized event
        # -----------------------------------------------------

        cur = conn.execute(
            """
            INSERT INTO events
            (
                raw_event_id,
                scan_id,
                event_type,
                source_ip,
                dest_ip,
                user,
                severity,
                timestamp,
                details,
                ioc_match
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_event_id,
                scan_id,
                event["event_type"],
                event["source_ip"],
                event["dest_ip"],
                event["user"],
                event["severity"],
                event["timestamp"],
                event["details"],
                ioc_match,
            ),
        )

        event_id = cur.lastrowid


        # -----------------------------------------------------
        # Update scan event count
        # -----------------------------------------------------

        if scan_id is not None:

            conn.execute(
                """
                UPDATE scan_sessions
                SET total_events = total_events + 1
                WHERE id = ?
                """,
                (scan_id,),
            )


        # -----------------------------------------------------
        # 4. RUN DETECTION RULES
        # -----------------------------------------------------

        triggered_rules = run_detections(
            conn,
            event,
            ioc_match,
        )


        # -----------------------------------------------------
        # Update scan threat count
        # -----------------------------------------------------

        if (
            scan_id is not None
            and triggered_rules
        ):

            conn.execute(
                """
                UPDATE scan_sessions
                SET threats_found = threats_found + 1
                WHERE id = ?
                """,
                (scan_id,),
            )


        # -----------------------------------------------------
        # 5. CORRELATE EVENT
        # -----------------------------------------------------

        incident = correlate(
            conn,
            event_id,
            event,
            triggered_rules,
        )


        # -----------------------------------------------------
        # 6. CREATE INCIDENT
        # -----------------------------------------------------

        if incident:

            score, level = score_incident(
                triggered_rules,
                len(
                    incident["event_ids"]
                ),
            )


            incident_id = save_incident(
                conn,
                user_id,
                incident["rules"],
                incident["event_ids"],
                score,
                level,
            )


            return {
                "event_id": event_id,
                "incident_id": incident_id,
                "alerts": triggered_rules,
                "incident_created": True,
                "risk_score": score,
                "risk_level": level,
            }


        # -----------------------------------------------------
        # No incident
        # -----------------------------------------------------

        return {
            "event_id": event_id,
            "alerts": triggered_rules,
            "incident_created": False,
            "risk_score": 0,
            "risk_level": "low",
        }