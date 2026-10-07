"""
Pipeline orchestration - ties layers 2 through 6 together for one event.

Flow:

Raw Event
    ↓
Normalize Event
    ↓
Threat Intelligence / IOC
    ↓
Store Event
    ↓
Detection Rules
    ↓
Correlation
    ↓
Risk Scoring
    ↓
Incident
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
    """
    Process one incoming security event.

    scan_id:
        Scan session that owns this event.

    user_id:
        User who owns the scan and event.
    """

    # =====================================================
    # 1. NORMALIZE EVENT
    # =====================================================

    event = normalize_event(raw_payload)

    # =====================================================
    # 2. THREAT INTELLIGENCE / IOC CHECK
    # =====================================================

    ioc_match = check_threat_intel(event)

    # =====================================================
    # 3. STORE NORMALIZED EVENT
    # =====================================================

    with db.session() as conn:

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

        # =================================================
        # 4. UPDATE SCAN EVENT COUNT
        # =================================================

        if scan_id is not None:

            conn.execute(
                """
                UPDATE scan_sessions
                SET total_events = total_events + 1
                WHERE id = ?
                  AND user_id = ?
                """,
                (
                    scan_id,
                    user_id,
                ),
            )

        # =================================================
        # 5. RUN DETECTION RULES
        # =================================================

        triggered_rules = run_detections(
            conn,
            event,
            ioc_match,
        )

        # =================================================
        # 6. CORRELATE
        # =================================================

        incident = correlate(
            conn,
            event_id,
            event,
            triggered_rules,
        )

        # =================================================
        # 7. NO INCIDENT
        # =================================================

        if not incident:

            return {
                "event_id": event_id,
                "alerts": triggered_rules,
                "incident_created": False,
                "risk_score": 0,
                "risk_level": "low",
            }

        # =================================================
        # 8. RISK SCORE
        # =================================================

        score, level = score_incident(
            triggered_rules,
            len(incident["event_ids"]),
        )

        # =================================================
        # 9. SAVE INCIDENT
        # =================================================

        incident_id = save_incident(
            conn,
            user_id,
            incident["rules"],
            incident["event_ids"],
            score,
            level,
        )

        # =================================================
        # 10. UPDATE THREAT COUNT
        # =================================================

        if scan_id is not None:

            conn.execute(
                """
                UPDATE scan_sessions
                SET threats_found = threats_found + 1
                WHERE id = ?
                  AND user_id = ?
                """,
                (
                    scan_id,
                    user_id,
                ),
            )

        # =================================================
        # 11. RETURN RESULT
        # =================================================

        return {
            "event_id": event_id,
            "incident_id": incident_id,
            "alerts": triggered_rules,
            "incident_created": True,
            "risk_score": score,
            "risk_level": level,
        }