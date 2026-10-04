"""
Backend API (Layer 7).

Exposes the ingestion endpoint collectors post to, plus read endpoints
the frontend dashboard consumes. Run with:

    python -m backend.app

from the project root (needs the root on the path so `database` and
`detection_engine` import cleanly - see the __main__ block below).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datetime import datetime, timezone
from flask import Flask, request, jsonify, g

from backend.config import Config, DB_PATH
from backend.auth import (
    require_api_key,
    require_auth,
    require_role,
    hash_password,
    verify_password,
    issue_token,
    VALID_ROLES,
)
from database.db import Database
from collectors.collector import store_raw_event
from detection_engine.pipeline import run_pipeline

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY

db = Database(DB_PATH)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"app": Config.APP_NAME, "env": Config.APP_ENV, "status": "ok"})


@app.route("/api/events", methods=["POST"])
@require_api_key
def ingest_event():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "invalid or missing JSON body"}), 400

    source = request.headers.get("X-Source", "unknown-collector")
    raw_event_id = store_raw_event(db, source, payload)
    result = run_pipeline(db, raw_event_id, payload)
    return jsonify(result), 201


@app.route("/api/auth/register", methods=["POST"])
def register():
    """Open only while the users table is empty (initial admin bootstrap).
    After that, only an authenticated admin can create more accounts."""
    body = request.get_json(force=True, silent=True) or {}
    username, password = body.get("username"), body.get("password")
    role = body.get("role", "analyst")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": f"role must be one of {sorted(VALID_ROLES)}"}), 400

    with db.session() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

        if user_count > 0:
            token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not token:
                return jsonify({"error": "registration is closed — ask an admin to create your account"}), 403
            from backend.auth import decode_token
            try:
                claims = decode_token(token)
            except Exception:
                return jsonify({"error": "invalid or expired token"}), 401
            if claims.get("role") != "admin":
                return jsonify({"error": "only an admin can register new accounts"}), 403
        else:
            role = "admin"  # first account created is always the bootstrap admin

        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return jsonify({"error": "username already taken"}), 409

        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, datetime.now(timezone.utc).isoformat()),
        )

    return jsonify({"username": username, "role": role}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    username, password = body.get("username"), body.get("password")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    with db.session() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "invalid username or password"}), 401

    token = issue_token(user["id"], user["username"], user["role"])
    return jsonify({"token": token, "role": user["role"], "expires_in_hours": 12})


@app.route("/api/events", methods=["GET"])
@require_auth
def list_events():
    with db.session() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/incidents", methods=["GET"])
@require_auth
def list_incidents():
    with db.session() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/incidents/<int:incident_id>", methods=["GET"])
@require_auth
def get_incident(incident_id):
    with db.session() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        incident = dict(row)
        event_ids = json.loads(incident["event_ids"])
        placeholders = ",".join("?" * len(event_ids))
        events = conn.execute(
            f"SELECT * FROM events WHERE id IN ({placeholders})", event_ids
        ).fetchall()
        incident["events"] = [dict(e) for e in events]
    return jsonify(incident)


@app.route("/api/incidents/<int:incident_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_incident(incident_id):
    """Admin-only example — copy this @require_auth + @require_role stack
    for any other route that shouldn't be open to every analyst."""
    with db.session() as conn:
        row = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
    return jsonify({"deleted": incident_id})


if __name__ == "__main__":
    Config.validate()
    db.init_schema()
    print(f"[{Config.APP_NAME}] starting in {Config.APP_ENV} mode — database: {DB_PATH}")
    app.run(debug=Config.DEBUG, port=5000)
