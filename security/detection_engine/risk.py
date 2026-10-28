"""
Risk Assessment (Layer 6)

Calculates a 0-100 risk score for a correlated incident
and stores the incident against the authenticated user.
"""

import json
from datetime import datetime, timezone


# ---------------------------------------------------------
# Severity weights
# ---------------------------------------------------------

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 45,
}


# ---------------------------------------------------------
# Calculate risk score
# ---------------------------------------------------------

def score_incident(
    triggered_rules: list[dict],
    related_event_count: int,
) -> tuple[int, str]:

    base = sum(
        SEVERITY_WEIGHTS.get(
            rule.get("severity", "low"),
            5,
        )
        for rule in triggered_rules
    )

    spread_bonus = min(
        related_event_count * 2,
        20,
    )

    score = min(
        base + spread_bonus,
        100,
    )


    # -----------------------------------------------------
    # Risk level
    # -----------------------------------------------------

    if score >= 75:
        level = "critical"

    elif score >= 50:
        level = "high"

    elif score >= 25:
        level = "medium"

    else:
        level = "low"


    return score, level


# ---------------------------------------------------------
# Save incident
# ---------------------------------------------------------

def save_incident(
    conn,
    user_id: int | None,
    rules: list[str],
    event_ids: list[int],
    score: int,
    level: str,
) -> int:

    # -----------------------------------------------------
    # Create incident title
    # -----------------------------------------------------

    if rules:
        title = (
            f"{rules[0].replace('_', ' ').title()} incident"
        )

    else:
        title = "Security incident"


    # -----------------------------------------------------
    # Insert incident
    # -----------------------------------------------------

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
            datetime.now(timezone.utc).isoformat(),
        ),
    )


    return cur.lastrowid