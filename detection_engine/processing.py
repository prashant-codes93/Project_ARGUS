"""
Processing layer (Layer 2).

Converts whatever shape a collector sends (field names vary by source)
into one consistent event schema everything downstream can rely on.
Add a branch here whenever a new collector uses different field names.
"""

from datetime import datetime, timezone


def normalize_event(raw_payload: dict) -> dict:
    return {
        "event_type": raw_payload.get("type", "unknown"),
        "source_ip": raw_payload.get("src_ip") or raw_payload.get("source_ip", ""),
        "dest_ip": raw_payload.get("dst_ip") or raw_payload.get("dest_ip", ""),
        "user": raw_payload.get("user", raw_payload.get("username", "")),
        "severity": raw_payload.get("severity", "low"),
        "timestamp": raw_payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "details": raw_payload.get("message", ""),
    }
