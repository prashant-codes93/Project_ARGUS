"""
Argus Backend API

Run from the project root:

    python -m backend.app

Architecture:

    Frontend
        ↓
    JWT Authentication
        ↓
    Flask REST API
        ↓
    SQLite Database
        ↓
    Argus Detection Pipeline
        ↓
    Alerts / Incidents / Risk
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# FLASK
# =========================================================

from flask import Flask, jsonify, request, g
from flask_cors import CORS


# =========================================================
# ARGUS MODULES
# =========================================================

from backend.config import Config, DB_PATH

from backend.auth import (
    require_auth,
    hash_password,
    verify_password,
    issue_token,
)

from database.db import Database
from collectors.collector import store_raw_event
from detection_engine.pipeline import run_pipeline


# =========================================================
# APP SETUP
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = Config.SECRET_KEY


# =========================================================
# CORS
# =========================================================
#
# Frontend:
#   http://127.0.0.1:5500
#
# Backend:
#   http://127.0.0.1:5000
#
# This allows the frontend to communicate with Flask.
# =========================================================

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://127.0.0.1:5500",
                "http://localhost:5500",
            ]
        }
    },
    supports_credentials=False,
)


# =========================================================
# DATABASE
# =========================================================

db = Database(DB_PATH)


# =========================================================
# HELPER
# =========================================================

def get_current_user_id():
    """
    Return the authenticated user's ID from the JWT.

    require_auth must run before this function is called.
    """

    try:
        return int(g.current_user["sub"])
    except (KeyError, TypeError, ValueError):
        return None


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "app": Config.APP_NAME,
        "env": Config.APP_ENV,
        "status": "ok",
    }), 200


# =========================================================
# REGISTER
# =========================================================

@app.route("/api/auth/register", methods=["POST"])
def register():
    """
    Register a new Argus user.

    Every normal registered user is an analyst.

    There is no admin hierarchy in the Argus application.
    """

    body = request.get_json(
        force=True,
        silent=True
    ) or {}

    username = body.get("username")
    password = body.get("password")

    # -----------------------------------------------------
    # Validate input
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
                "error": "username already taken"
            }), 409

        # Every new user is a normal analyst.
        role = "analyst"

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
                hash_password(password),
                role,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        user_id = cursor.lastrowid

    return jsonify({
        "message": "registration successful",
        "user": {
            "id": user_id,
            "username": username,
            "role": role,
        },
    }), 201


# =========================================================
# LOGIN
# =========================================================

@app.route("/api/auth/login", methods=["POST"])
def login():

    body = request.get_json(
        force=True,
        silent=True
    ) or {}

    username = body.get("username")
    password = body.get("password")

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
    # Verify credentials
    # -----------------------------------------------------

    if not user:
        return jsonify({
            "error": "invalid username or password"
        }), 401

    if not verify_password(
        password,
        user["password_hash"]
    ):
        return jsonify({
            "error": "invalid username or password"
        }), 401

    # -----------------------------------------------------
    # Create fresh JWT
    # -----------------------------------------------------

    token = issue_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role"],
    )

    return jsonify({
        "message": "login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        },
    }), 200


# =========================================================
# CREATE SCAN
# =========================================================

@app.route("/api/scans", methods=["POST"])
@require_auth
def create_scan():

    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({
            "error": "invalid authenticated user"
        }), 401

    with db.session() as conn:

        cursor = conn.execute(
            """
            INSERT INTO scan_sessions
            (
                user_id,
                started_at,
                status,
                total_events,
                threats_found
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                datetime.now(timezone.utc).isoformat(),
                "active",
                0,
                0,
            ),
        )

        scan_id = cursor.lastrowid

    return jsonify({
        "scan_id": scan_id,
        "status": "active",
    }), 201


# =========================================================
# GET SCAN HISTORY
# =========================================================

@app.route("/api/scans", methods=["GET"])
@require_auth
def list_scans():

    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({
            "error": "invalid authenticated user"
        }), 401

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
# INGEST EVENT / LOG UPLOAD
# =========================================================

@app.route("/api/events", methods=["POST"])
@require_auth
def ingest_event():

    # -----------------------------------------------------
    # Get authenticated user
    # -----------------------------------------------------

    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({
            "error": "invalid authenticated user"
        }), 401

    # -----------------------------------------------------
    # Read JSON
    # -----------------------------------------------------

    payload = request.get_json(
        force=True,
        silent=True
    )

    if not payload:
        return jsonify({
            "error": "invalid or missing JSON body"
        }), 400

    # -----------------------------------------------------
    # Get scan ID
    # -----------------------------------------------------

    scan_id = request.headers.get("X-Scan-ID")

    if not scan_id:
        return jsonify({
            "error": "X-Scan-ID header is required"
        }), 400

    try:
        scan_id = int(scan_id)
    except (ValueError, TypeError):
        return jsonify({
            "error": "X-Scan-ID must be a number"
        }), 400

    # -----------------------------------------------------
    # Verify scan ownership
    # -----------------------------------------------------
    #
    # User A cannot upload into User B's scan.
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
                user_id,
            ),
        ).fetchone()

    if not scan:
        return jsonify({
            "error": "scan not found or does not belong to this user"
        }), 403

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

    try:

        raw_event_id = store_raw_event(
            db,
            source,
            payload
        )

    except Exception as exc:

        app.logger.exception(
            "Failed to store raw event"
        )

        return jsonify({
            "error": "failed to store event",
            "details": str(exc),
        }), 500

    # -----------------------------------------------------
    # Run Argus detection pipeline
    # -----------------------------------------------------

    try:

        result = run_pipeline(
            db,
            raw_event_id,
            payload,
            scan_id=scan_id,
            user_id=user_id,
        )

    except Exception as exc:

        app.logger.exception(
            "Argus pipeline failed"
        )

        return jsonify({
            "error": "detection pipeline failed",
            "details": str(exc),
        }), 500

    return jsonify(result), 201


# =========================================================
# GET EVENTS
# =========================================================

@app.route("/api/events", methods=["GET"])
@require_auth
def list_events():

    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({
            "error": "invalid authenticated user"
        }), 401

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

    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({
            "error": "invalid authenticated user"
        }), 401

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

@app.route("/api/incidents/<int:incident_id>", methods=["GET"])
@require_auth
def get_incident(incident_id):

    user_id = get_current_user_id()

    if user_id is None:
        return jsonify({
            "error": "invalid authenticated user"
        }), 401

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
                user_id,
            ),
        ).fetchone()

        if not row:
            return jsonify({
                "error": "incident not found"
            }), 404

        incident = dict(row)

        # -------------------------------------------------
        # Decode related event IDs
        # -------------------------------------------------

        try:

            event_ids = json.loads(
                incident.get("event_ids", "[]")
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):

            event_ids = []

        # -------------------------------------------------
        # Get related events
        # -------------------------------------------------

        if event_ids:

            placeholders = ",".join(
                "?" for _ in event_ids
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
                event_ids + [user_id],
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

    Config.validate()

    db.init_schema()

    print(
        f"[{Config.APP_NAME}] "
        f"starting in {Config.APP_ENV} mode "
        f"— database: {DB_PATH}"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=Config.DEBUG,
    )