"""Email-verified registration for ARGUS."""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from flask import jsonify, request
from backend.auth import hash_password
from backend.config import Config
from backend.email_service import send_otp_email

OTP_EXPIRY_MINUTES = 5
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5

def create_otp_hash(otp):
    """Create a secure hash of an OTP."""

    return hmac.new(
        Config.SECRET_KEY.encode(),
        otp.encode(),
        hashlib.sha256,
    ).hexdigest()

def install_otp_routes(app, db):
    def ensure_schema(conn):
        if "email" not in {row[1] for row in conn.execute("PRAGMA table_info(users)")}:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("""CREATE TABLE IF NOT EXISTS email_verifications (
            email TEXT NOT NULL UNIQUE, username TEXT NOT NULL, password_hash TEXT NOT NULL,
            otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL)""")

    @app.post("/api/auth/register")
    def register():

        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON object required"), 400

        username = str(body.get("username", "")).strip()
        email = str(body.get("email", "")).strip().lower()
        password = body.get("password", "")

        # -----------------------------------------------------
        # VALIDATION
        # -----------------------------------------------------

        if not username or not email or not password:
            return jsonify({
                "error": "username, email and password are required"
            }), 400

        if len(username) < 3 or len(username) > 50:
            return jsonify({
                "error": "username must be between 3 and 50 characters"
            }), 400

        if not isinstance(password, str) or len(password) < 6:
            return jsonify({
                "error": "password must contain at least 6 characters"
            }), 400

        if len(email) > 254 or not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email,
        ):
            return jsonify({
                "error": "invalid email address"
            }), 400

        # -----------------------------------------------------
        # GENERATE OTP
        # -----------------------------------------------------

        otp = str(secrets.randbelow(900000) + 100000)

        otp_hash = create_otp_hash(otp)

        now = datetime.now(timezone.utc)

        expires_at = (
            now + timedelta(minutes=OTP_EXPIRY_MINUTES)
        ).isoformat()

        # -----------------------------------------------------
        # CHECK EXISTING ACCOUNTS AND PENDING REGISTRATIONS
        # -----------------------------------------------------

        with db.session() as conn:
            conn.execute("BEGIN IMMEDIATE")
            ensure_schema(conn)

            existing = conn.execute(
                """
                SELECT id
                FROM users
                WHERE username = ? OR email = ?
                """,
                (username, email),
            ).fetchone()

            if existing:
                return jsonify({
                    "error": "username or email already registered"
                }), 409

            pending = conn.execute(
                """
                SELECT username, created_at
                FROM email_verifications
                WHERE email = ?
                """,
                (email,),
            ).fetchone()

            if pending:

                previous_time = datetime.fromisoformat(
                    pending["created_at"]
                )

                if now - previous_time < timedelta(
                    seconds=OTP_RESEND_SECONDS
                ):
                    return jsonify({
                        "error": "please wait before requesting another OTP"
                    }), 429

                conn.execute(
                    """
                    DELETE FROM email_verifications
                    WHERE email = ?
                    """,
                    (email,),
                )

            conn.execute(
                """
                INSERT INTO email_verifications
                (
                    email,
                    username,
                    password_hash,
                    otp_hash,
                    expires_at,
                    attempts,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    email,
                    username,
                    hash_password(password),
                    otp_hash,
                    expires_at,
                    now.isoformat(),
                ),
            )

        # -----------------------------------------------------
        # SEND OTP USING BREVO
        # -----------------------------------------------------

        try:

            send_otp_email(email, otp)

        except Exception:

            app.logger.exception(
                "Failed to send registration OTP"
            )

            with db.session() as conn:
                conn.execute(
                    """
                    DELETE FROM email_verifications
                    WHERE email = ? AND otp_hash = ?
                    """,
                    (email, otp_hash),
                )

            return jsonify({
                "error": "could not send verification email"
            }), 502

        return jsonify({
            "message": "OTP sent successfully. Check your email.",
            "email": email,
        }), 200

    @app.post("/api/auth/verify-otp")
    def verify_registration_otp():

        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON object required"), 400

        email = str(body.get("email", "")).strip().lower()
        otp = str(body.get("otp", "")).strip()

        if not email or not re.fullmatch(r"\d{6}", otp):
            return jsonify({
                "error": "valid email and 6-digit OTP are required"
            }), 400

        with db.session() as conn:
            conn.execute("BEGIN IMMEDIATE")
            ensure_schema(conn)

            pending = conn.execute(
                """
                SELECT *
                FROM email_verifications
                WHERE email = ?
                """,
                (email,),
            ).fetchone()

            if not pending:
                return jsonify({
                    "error": "no pending verification found"
                }), 404

            now = datetime.now(timezone.utc)

            expiry = datetime.fromisoformat(
                pending["expires_at"]
            )

            # -------------------------------------------------
            # CHECK EXPIRY
            # -------------------------------------------------

            if now >= expiry:

                conn.execute(
                    """
                    DELETE FROM email_verifications
                    WHERE email = ?
                    """,
                    (email,),
                )

                return jsonify({
                    "error": "OTP expired. Please register again."
                }), 400

            # -------------------------------------------------
            # CHECK ATTEMPTS
            # -------------------------------------------------

            if pending["attempts"] >= OTP_MAX_ATTEMPTS:

                conn.execute(
                    """
                    DELETE FROM email_verifications
                    WHERE email = ?
                    """,
                    (email,),
                )

                return jsonify({
                    "error": "too many incorrect attempts. Please register again."
                }), 429

            # -------------------------------------------------
            # VERIFY OTP
            # -------------------------------------------------

            submitted_hash = create_otp_hash(otp)

            if not hmac.compare_digest(
                submitted_hash,
                pending["otp_hash"],
            ):

                attempts = pending["attempts"] + 1

                if attempts >= OTP_MAX_ATTEMPTS:

                    conn.execute(
                        """
                        DELETE FROM email_verifications
                        WHERE email = ?
                        """,
                        (email,),
                    )

                else:

                    conn.execute(
                        """
                        UPDATE email_verifications
                        SET attempts = ?
                        WHERE email = ?
                        """,
                        (attempts, email),
                    )

                return jsonify({
                    "error": "incorrect OTP"
                }), 400

            # -------------------------------------------------
            # CREATE VERIFIED ACCOUNT
            # -------------------------------------------------

            try:

                cursor = conn.execute(
                    """
                    INSERT INTO users
                    (
                        username,
                        email,
                        password_hash,
                        role,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        pending["username"],
                        email,
                        pending["password_hash"],
                        "analyst",
                        now.isoformat(),
                    ),
                )

            except Exception:

                app.logger.exception(
                    "Failed to create verified user"
                )

                return jsonify({
                    "error": "could not create account. Username or email may already exist."
                }), 409

            user_id = cursor.lastrowid

            conn.execute(
                """
                DELETE FROM email_verifications
                WHERE email = ?
                """,
                (email,),
            )

        return jsonify({
            "message": "email verified and registration successful",
            "user": {
                "id": user_id,
                "username": pending["username"],
                "email": email,
                "role": "analyst",
            },
        }), 201
