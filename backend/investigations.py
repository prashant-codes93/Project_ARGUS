from datetime import datetime, timezone

from flask import jsonify, request

from backend.auth import require_auth


STATUSES = {"open", "in_progress", "under_review", "resolved"}
SEVERITIES = {"low", "medium", "high", "critical"}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def register_investigations(app, db, get_current_user_id):
    with db.session() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_cases (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                incident_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                analyst TEXT NOT NULL,
                escalated INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_activity (
                id INTEGER PRIMARY KEY,
                case_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES investigation_cases(id)
            )
        """)

    def current_name(conn, user_id):
        row = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return row["username"] if row else None

    def log(conn, case_id, kind, body, author, now):
        conn.execute(
            """
            INSERT INTO investigation_activity
                (case_id, kind, body, author, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (case_id, kind, body, author, now),
        )

    @app.route("/api/investigations", methods=["GET"])
    @require_auth
    def investigations_list():
        user_id = get_current_user_id()
        with db.session() as conn:
            name = current_name(conn, user_id)
            if name is None:
                return jsonify({"error": "Unknown account"}), 401

            rows = conn.execute(
                """
                SELECT *
                FROM investigation_cases
                WHERE user_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (user_id,),
            ).fetchall()

        return jsonify({
            "username": name,
            "cases": [dict(row) for row in rows],
        })

    @app.route("/api/investigations", methods=["POST"])
    @require_auth
    def investigations_create():
        user_id = get_current_user_id()
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Expected a JSON object"}), 400

        title = data.get("title")
        description = data.get("description", "")
        incident_id = data.get("incident_id")
        severity = data.get("severity")
        status = data.get("status", "open")
        analyst = data.get("analyst", "Unassigned")

        if not isinstance(title, str) or not title.strip():
            return jsonify({"error": "Enter an investigation title"}), 400
        if not isinstance(description, str):
            return jsonify({"error": "Invalid description"}), 400
        if type(incident_id) is not int or incident_id <= 0:
            return jsonify({"error": "Select a related alert"}), 400
        if not isinstance(severity, str) or severity not in SEVERITIES:
            return jsonify({"error": "Invalid severity"}), 400
        if not isinstance(status, str) or status not in STATUSES:
            return jsonify({"error": "Invalid status"}), 400

        with db.session() as conn:
            name = current_name(conn, user_id)
            if name is None:
                return jsonify({"error": "Unknown account"}), 401
            if analyst not in ("Unassigned", name):
                return jsonify({"error": "Invalid analyst"}), 400

            incident = conn.execute(
                "SELECT id FROM incidents WHERE id = ? AND user_id = ?",
                (incident_id, user_id),
            ).fetchone()
            if not incident:
                return jsonify({"error": "Related alert not found"}), 404

            now = timestamp()
            cursor = conn.execute(
                """
                INSERT INTO investigation_cases (
                    user_id, incident_id, title, description, severity,
                    status, analyst, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, incident_id, title.strip(), description.strip(),
                    severity, status, analyst, now, now,
                ),
            )
            case_id = cursor.lastrowid
            log(conn, case_id, "activity", "Investigation created", name, now)

        return jsonify({"id": case_id}), 201

    @app.route("/api/investigations/<int:case_id>/activity", methods=["GET", "POST"])
    @require_auth
    def investigation_activity(case_id):
        user_id = get_current_user_id()

        with db.session() as conn:
            case = conn.execute(
                "SELECT id FROM investigation_cases WHERE id = ? AND user_id = ?",
                (case_id, user_id),
            ).fetchone()
            if not case:
                return jsonify({"error": "Investigation not found"}), 404

            if request.method == "GET":
                rows = conn.execute(
                    """
                    SELECT kind, body, author, created_at
                    FROM investigation_activity
                    WHERE case_id = ?
                    ORDER BY id
                    """,
                    (case_id,),
                ).fetchall()
                return jsonify([dict(row) for row in rows])

            name = current_name(conn, user_id)
            if name is None:
                return jsonify({"error": "Unknown account"}), 401

            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Expected a JSON object"}), 400

            action = data.get("action")
            value = data.get("value", "")
            if not isinstance(value, str):
                return jsonify({"error": "Invalid value"}), 400
            value = value.strip()
            now = timestamp()
            kind = "activity"

            if action == "status" and value in STATUSES:
                conn.execute(
                    "UPDATE investigation_cases SET status = ? WHERE id = ?",
                    (value, case_id),
                )
                body = "Status changed to " + value.replace("_", " ")
            elif action == "assign" and value in ("Unassigned", name):
                conn.execute(
                    "UPDATE investigation_cases SET analyst = ? WHERE id = ?",
                    (value, case_id),
                )
                body = "Assigned to " + value
            elif action == "escalate":
                changed = conn.execute(
                    """
                    UPDATE investigation_cases SET escalated = 1
                    WHERE id = ? AND escalated = 0 AND status != 'resolved'
                    """,
                    (case_id,),
                ).rowcount
                if not changed:
                    return jsonify({"error": "Case already escalated or resolved"}), 409
                body = "Investigation escalated"
            elif action in ("note", "evidence") and value:
                kind = action
                body = value
            else:
                return jsonify({"error": "Enter a valid action and value"}), 400

            conn.execute(
                "UPDATE investigation_cases SET updated_at = ? WHERE id = ?",
                (now, case_id),
            )
            log(conn, case_id, kind, body, name, now)

        return jsonify({"saved": True})