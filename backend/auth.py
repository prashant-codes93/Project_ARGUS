"""
Auth (part of Layer 7).

Two separate auth models on purpose, because collectors and humans have
different needs:

  - Collectors (machines) use a shared API key via require_api_key().
    They have no accounts and shouldn't need one.
  - Analysts and admins (humans, using the dashboard) use real accounts:
    hashed passwords, a JWT issued at login, and a role checked on every
    protected route via require_auth() / require_role().

Register the first account through /api/auth/register — that route only
allows open self-registration while the users table is empty (bootstrap),
then requires an existing admin token for every registration after that.
"""

from functools import wraps
from datetime import datetime, timedelta, timezone

import jwt
from flask import request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

from backend.config import Config

TOKEN_EXPIRY_HOURS = 12
VALID_ROLES = {"admin", "analyst"}


# ---------------------------------------------------------------------
# Machine auth — collectors posting events
# ---------------------------------------------------------------------

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if key != Config.API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------
# Human auth — accounts, passwords, JWTs
# ---------------------------------------------------------------------

def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def issue_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])


def _extract_bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ").strip()


def require_auth(f):
    """Requires any valid, non-expired token. Attaches g.current_user."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        token = _extract_bearer_token()
        if not token:
            return jsonify({"error": "missing bearer token"}), 401
        try:
            g.current_user = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)

    return wrapper


def require_role(*allowed_roles):
    """Stack under require_auth: @require_auth then @require_role('admin')."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.current_user.get("role") not in allowed_roles:
                return jsonify({"error": "forbidden — insufficient role"}), 403
            return f(*args, **kwargs)

        return wrapper

    return decorator
