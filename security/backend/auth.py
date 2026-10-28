"""
Argus Authentication
====================

Handles authentication for:

1. Machine/collector requests
   - Uses X-API-Key
   - Used by collectors that send security events

2. Human/dashboard requests
   - Uses username + password
   - Passwords are securely hashed
   - Login returns a JWT
   - Protected API routes require a valid JWT

JWT payload contains:
    sub       -> user ID as a STRING
    username  -> username
    role      -> user role
    exp       -> token expiration time
"""

from functools import wraps
from datetime import datetime, timedelta, timezone

import jwt
from flask import request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

from backend.config import Config


# ============================================================
# JWT SETTINGS
# ============================================================

TOKEN_EXPIRY_HOURS = 12

# Argus currently treats normal registered users as analysts.
VALID_ROLES = {"analyst"}


# ============================================================
# MACHINE / COLLECTOR AUTHENTICATION
# ============================================================

def require_api_key(f):
    """
    Authenticate machine/collector requests using X-API-Key.

    Example header:

        X-API-Key: your-api-key
    """

    @wraps(f)
    def wrapper(*args, **kwargs):

        key = request.headers.get("X-API-Key")

        if not key:
            return jsonify({
                "error": "missing API key"
            }), 401

        if key != Config.API_KEY:
            return jsonify({
                "error": "unauthorized"
            }), 401

        return f(*args, **kwargs)

    return wrapper


# ============================================================
# PASSWORD FUNCTIONS
# ============================================================

def hash_password(password: str) -> str:
    """
    Hash a user's password before storing it in the database.
    """

    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plain-text password against its stored hash.
    """

    return check_password_hash(password_hash, password)


# ============================================================
# JWT CREATION
# ============================================================

def issue_token(user_id: int, username: str, role: str) -> str:
    """
    Create a JWT for an authenticated user.

    IMPORTANT:
    JWT 'sub' is stored as a STRING because PyJWT validates
    the subject claim as a string.
    """

    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": (
            datetime.now(timezone.utc)
            + timedelta(hours=TOKEN_EXPIRY_HOURS)
        ),
    }

    token = jwt.encode(
        payload,
        Config.SECRET_KEY,
        algorithm="HS256"
    )

    return token


# ============================================================
# JWT DECODING
# ============================================================

def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT.

    Raises a PyJWT exception if:
    - token is invalid
    - signature is invalid
    - token has expired
    """

    return jwt.decode(
        token,
        Config.SECRET_KEY,
        algorithms=["HS256"]
    )


# ============================================================
# EXTRACT BEARER TOKEN
# ============================================================

def _extract_bearer_token() -> str | None:
    """
    Read:

        Authorization: Bearer <token>

    from the incoming HTTP request.
    """

    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None

    token = header.removeprefix("Bearer ").strip()

    if not token:
        return None

    return token


# ============================================================
# JWT AUTHENTICATION DECORATOR
# ============================================================

def require_auth(f):
    """
    Protect an API endpoint with JWT authentication.

    A valid token is required.

    After successful validation:

        g.current_user

    contains the JWT claims.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):

        token = _extract_bearer_token()

        # ----------------------------------------------------
        # No token
        # ----------------------------------------------------

        if not token:
            return jsonify({
                "error": "missing bearer token"
            }), 401

        # ----------------------------------------------------
        # Validate token
        # ----------------------------------------------------

        try:

            claims = decode_token(token)

            # ------------------------------------------------
            # Make sure subject exists
            # ------------------------------------------------

            if "sub" not in claims:
                return jsonify({
                    "error": "invalid token — missing user ID"
                }), 401

            # ------------------------------------------------
            # Store authenticated user information
            # ------------------------------------------------

            g.current_user = claims

        except jwt.ExpiredSignatureError:

            return jsonify({
                "error": "token expired"
            }), 401

        except jwt.InvalidTokenError:

            return jsonify({
                "error": "invalid token"
            }), 401

        # ----------------------------------------------------
        # Continue to protected endpoint
        # ----------------------------------------------------

        return f(*args, **kwargs)

    return wrapper


# ============================================================
# ROLE AUTHENTICATION
# ============================================================

def require_role(*allowed_roles):
    """
    Optional role-based protection.

    Example:

        @require_auth
        @require_role("analyst")

    The decorator is kept for compatibility with existing
    routes, although Argus currently uses analyst accounts
    for normal registered users.
    """

    def decorator(f):

        @wraps(f)
        def wrapper(*args, **kwargs):

            current_user = getattr(g, "current_user", {})

            user_role = current_user.get("role")

            if user_role not in allowed_roles:

                return jsonify({
                    "error": "forbidden — insufficient role"
                }), 403

            return f(*args, **kwargs)

        return wrapper

    return decorator