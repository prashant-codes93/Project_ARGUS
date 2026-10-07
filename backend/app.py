"""
ARGUS Backend API

Layer 7 Backend

Main responsibilities:

- User registration
- User login
- JWT authentication
- User-specific scan management
- User-specific log/event ingestion
- Detection pipeline
- User-specific event retrieval
- User-specific incident retrieval

Each registered user has completely separate:
- scans
- uploaded logs
- events
- alerts
- incidents
- dashboard data

There is no admin panel or admin hierarchy.

Run from project root:

    python -m backend.app
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request, g
from flask_cors import CORS


# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# ARGUS IMPORTS
# =========================================================

from backend.auth import (
    issue_token,
    hash_password,
    verify_password,
    require_auth,
)

from backend.config import Config, DB_PATH

from database.db import Database

from collectors.collector import store_raw_event

from detection_engine.pipeline import run_pipeline


# =========================================================
# APP SETUP
# =========================================================

app = Flask(__name__)

CORS(app)

app.config["SECRET_KEY"] = Config.SECRET_KEY

db = Database(DB_PATH)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok",
        "service": "Argus backend"
    }), 200


# =========================================================
# USER REGISTRATION
# =========================================================

@app.route("/api/auth/register", methods=["POST"])
def register():

    payload = request.get_json(
        force=True,
        silent=True
    ) or {}

    username = payload.get("username")
    password = payload.get("password")

    # -----------------------------------------------------
    # Validate username and password
    # -----------------------------------------------------

    if not username or not password:

        return jsonify({
            "error": "username and password are required"
        }), 400

    username = str(username).strip()

    if len(username) < 3:

        return jsonify({
            "error": "username must be at least 3 characters"
        }), 400

    if len(password) < 6:

        return jsonify({
            "error": "password must be at least 6 characters"
        }), 400

    # -----------------------------------------------------
    # Create user
    # -----------------------------------------------------

    with db.session() as conn:

        # Check duplicate username

        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if existing:

            return jsonify({
                "error": "username already exists"
            }), 409

        # -------------------------------------------------
        # Every normal registration is a normal user
        # -------------------------------------------------

        role = "analyst"

        # -------------------------------------------------
        # Hash password
        # -------------------------------------------------

        password_hash = hash_password(password)

        # -------------------------------------------------
        # Insert user
        # -------------------------------------------------

        cursor = conn.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                role,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                password_hash,
                role,
                datetime.now(timezone.utc).isoformat()
            )
        )

        user_id = cursor.lastrowid

    # -----------------------------------------------------
    # Registration successful
    # -----------------------------------------------------

    return jsonify({
        "message": "registration successful",
        "user_id": user_id,
        "username": username
    }), 201


# =========================================================
# USER LOGIN
# =========================================================

@app.route("/api/auth/login", methods=["POST"])
def login():

    payload = request.get_json(
        force=True,
        silent=True
    ) or {}

    username = payload.get("username")
    password = payload.get("password")

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not username or not password:

        return jsonify({
            "error": "username and password are required"
        }), 400

    username = str(username).strip()

    # -----------------------------------------------------
    # Find user
    # -----------------------------------------------------

    with db.session() as conn:

        user = conn.execute(
            """
            SELECT
                id,
                username,
                password_hash,
                role
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

    # -----------------------------------------------------
    # User doesn't exist
    # -----------------------------------------------------

    if not user:

        return jsonify({
            "error": "invalid username or password"
        }), 401

    # -----------------------------------------------------
    # Verify password
    # -----------------------------------------------------

    if not verify_password(
        password,
        user["password_hash"]
    ):

        return jsonify({
            "error": "invalid username or password"
        }), 401

    # -----------------------------------------------------
    # Generate JWT token
    # -----------------------------------------------------

    token = issue_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role"]
    )

    # -----------------------------------------------------
    # Login successful
    # -----------------------------------------------------

    return jsonify({
        "message": "login successful",

        "token": token,

        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }), 200


# =========================================================
# CREATE NEW SCAN
# =========================================================

@app.route("/api/scans", methods=["POST"])
@require_auth
def create_scan():

    user_id = int(g.current_user["sub"])

    with db.session() as conn:

        cursor = conn.execute(
            """
            INSERT INTO scan_sessions
            (
                user_id,
                started_at,
                status
            )
            VALUES (?, ?, ?)
            """,
            (
                user_id,
                datetime.now(timezone.utc).isoformat(),
                "active"
            )
        )

        scan_id = cursor.lastrowid

    return jsonify({
        "scan_id": scan_id,
        "status": "active"
    }), 201


# =========================================================
# GET SCAN HISTORY
# =========================================================

@app.route("/api/scans", methods=["GET"])
@require_auth
def list_scans():

    user_id = int(g.current_user["sub"])

    with db.session() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                started_at,
                ended_at,
                status,
                total_events,
                threats_found
            FROM scan_sessions
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,)
        ).fetchall()

    return jsonify([
        dict(row)
        for row in rows
    ]), 200


# =========================================================
# INGEST EVENT / LOG
# =========================================================

@app.route("/api/events", methods=["POST"])
@require_auth
def ingest_event():

    user_id = int(g.current_user["sub"])

    payload = request.get_json(
        force=True,
        silent=True
    )

    # -----------------------------------------------------
    # Validate payload
    # -----------------------------------------------------

    if not payload:

        return jsonify({
            "error": "invalid or missing JSON body"
        }), 400

    # -----------------------------------------------------
    # Get Scan ID
    # -----------------------------------------------------

    scan_id = request.headers.get("X-Scan-ID")

    if not scan_id:

        return jsonify({
            "error": "X-Scan-ID header is required"
        }), 400

    # -----------------------------------------------------
    # Convert Scan ID to integer
    # -----------------------------------------------------

    try:

        scan_id = int(scan_id)

    except (ValueError, TypeError):

        return jsonify({
            "error": "X-Scan-ID must be a number"
        }), 400

    # -----------------------------------------------------
    # Verify scan belongs to logged-in user
    # -----------------------------------------------------

    with db.session() as conn:

        scan = conn.execute(
            """
            SELECT
                id,
                user_id,
                status
            FROM scan_sessions
            WHERE id = ?
              AND user_id = ?
            """,
            (
                scan_id,
                user_id
            )
        ).fetchone()

    if not scan:

        return jsonify({
            "error": "scan not found or does not belong to this user"
        }), 404

    if scan["status"] != "active":

        return jsonify({
            "error": "scan is not active"
        }), 400

    # -----------------------------------------------------
    # Source
    # -----------------------------------------------------

    source = request.headers.get(
        "X-Source",
        "dashboard-upload"
    )

    # -----------------------------------------------------
    # Store raw event
    # -----------------------------------------------------

    raw_event_id = store_raw_event(
        db,
        source,
        payload
    )

    # -----------------------------------------------------
    # Run ARGUS detection pipeline
    # -----------------------------------------------------

    result = run_pipeline(
        db,
        raw_event_id,
        payload,
        scan_id=scan_id,
        user_id=user_id
    )

    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return jsonify(result), 201


# =========================================================
# GET EVENTS
# =========================================================

@app.route("/api/events", methods=["GET"])
@require_auth
def list_events():

    user_id = int(g.current_user["sub"])

    with db.session() as conn:

        rows = conn.execute(
            """
            SELECT e.*
            FROM events e
            JOIN scan_sessions s
                ON e.scan_id = s.id
            WHERE s.user_id = ?
            ORDER BY e.timestamp DESC
            LIMIT 200
            """,
            (user_id,)
        ).fetchall()

    return jsonify([
        dict(row)
        for row in rows
    ]), 200


# =========================================================
# GET INCIDENTS
# =========================================================

@app.route("/api/incidents", methods=["GET"])
@require_auth
def list_incidents():

    user_id = int(g.current_user["sub"])

    with db.session() as conn:

        rows = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,)
        ).fetchall()

    return jsonify([
        dict(row)
        for row in rows
    ]), 200


# =========================================================
# GET SINGLE INCIDENT
# =========================================================

@app.route(
    "/api/incidents/<int:incident_id>",
    methods=["GET"]
)
@require_auth
def get_incident(incident_id):

    user_id = int(g.current_user["sub"])

    with db.session() as conn:

        # -------------------------------------------------
        # Get incident belonging to current user
        # -------------------------------------------------

        row = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
              AND user_id = ?
            """,
            (
                incident_id,
                user_id
            )
        ).fetchone()

        if not row:

            return jsonify({
                "error": "incident not found"
            }), 404

        incident = dict(row)

        # -------------------------------------------------
        # Get related event IDs
        # -------------------------------------------------

        try:

            event_ids = json.loads(
                incident.get("event_ids", "[]")
            )

        except (json.JSONDecodeError, TypeError):

            event_ids = []

        # -------------------------------------------------
        # Get related events
        # -------------------------------------------------

        if event_ids:

            placeholders = ",".join(
                "?"
                for _ in event_ids
            )

            events = conn.execute(
                f"""
                SELECT e.*
                FROM events e
                JOIN scan_sessions s
                    ON e.scan_id = s.id
                WHERE e.id IN ({placeholders})
                  AND s.user_id = ?
                """,
                event_ids + [user_id]
            ).fetchall()

            incident["events"] = [
                dict(event)
                for event in events
            ]

        else:

            incident["events"] = []

    return jsonify(incident), 200


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    print("[Argus] starting...")

    # -----------------------------------------------------
    # Validate configuration
    # -----------------------------------------------------

    Config.validate()

    # -----------------------------------------------------
    # Make sure database tables exist
    # -----------------------------------------------------

    db.init_schema()

    # -----------------------------------------------------
    # Start Flask server
    # -----------------------------------------------------

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=Config.DEBUG
    )