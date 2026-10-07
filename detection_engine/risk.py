"""
Risk assessment (Layer 6).

Turns a correlated incident into a 0-100 risk score and a human-readable
level. SEVERITY_WEIGHTS and the score thresholds are a starting point -
the dev team should calibrate these against real incident data before
relying on them to drive on-call urgency.
"""

import json
from datetime import datetime, timezone

SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 30, "critical": 45}


def score_incident(triggered_rules: list[dict], related_event_count: int) -> tuple[int, str]:
    base = sum(SEVERITY_WEIGHTS.get(r["severity"], 5) for r in triggered_rules)
    spread_bonus = min(related_event_count * 2, 20)
    score = min(base + spread_bonus, 100)

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return score, level


def save_incident(
    conn,
    user_id: int,
    rules: list[str],
    event_ids: list[int],
    score: int,
    level: str
) -> int:
    title = f"{rules[0].replace('_', ' ').title()} incident"

    cur = conn.execute(
        """
        INSERT INTO incidents
        (
            user_id,
            title,
            event_ids,
            risk_score,
            risk_level,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            title,
            json.dumps(event_ids),
            score,
            level,
            datetime.now(timezone.utc).isoformat()
        ),
    )

    return cur.lastrowid
