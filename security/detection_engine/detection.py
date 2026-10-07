"""
Detection engine (Layer 3).

Rule-based detections run against a normalized event plus its
threat-intel result. Each rule returns an alert dict with a severity;
run_detections() collects everything that fired. Add new rules as their
own function and call them from run_detections() to keep each rule
independently testable.
"""

from datetime import datetime, timedelta

FAILED_LOGIN_WINDOW_MIN = 5
FAILED_LOGIN_THRESHOLD = 5


def rule_known_malicious_ip(ioc_match: int) -> dict | None:
    if ioc_match:
        return {"rule": "known_malicious_ip", "severity": "high"}
    return None


def rule_brute_force_login(conn, event: dict) -> dict | None:
    if event["event_type"] != "failed_login":
        return None
    window_start = (
        datetime.fromisoformat(event["timestamp"]) - timedelta(minutes=FAILED_LOGIN_WINDOW_MIN)
    ).isoformat()
    count = conn.execute(
        """SELECT COUNT(*) AS c FROM events
           WHERE event_type = 'failed_login' AND user = ? AND timestamp >= ?""",
        (event["user"], window_start),
    ).fetchone()["c"]
    if count >= FAILED_LOGIN_THRESHOLD:
        return {"rule": "brute_force_login", "severity": "high"}
    return None


def rule_large_data_export(event: dict) -> dict | None:
    if event["event_type"] == "data_export" and event["severity"] in ("high", "critical"):
        return {"rule": "large_data_export", "severity": "medium"}
    return None


def run_detections(conn, event: dict, ioc_match: int) -> list[dict]:
    alerts = [
        rule_known_malicious_ip(ioc_match),
        rule_brute_force_login(conn, event),
        rule_large_data_export(event),
    ]
    return [a for a in alerts if a is not None]
