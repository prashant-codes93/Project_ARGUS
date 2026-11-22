import json
import sqlite3
from datetime import datetime, timezone
from ipaddress import IPv4Address

from flask import jsonify, request
from backend.auth import require_auth


FIELDS = "name type ip mac host os osv owner loc crit env desc sec".split()
TYPES = ("Server", "Workstation", "Network Device", "Cloud Resource", "Database", "Other")


def register_assets(app, db, get_current_user_id):
    with db.session() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS asset_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                profile TEXT NOT NULL,
                online INTEGER,
                created TEXT NOT NULL,
                UNIQUE (user_id, ip)
            )
        """)

    @app.route("/api/assets", methods=["GET", "POST"])
    @app.route("/api/assets/<int:asset_id>", methods=["PUT", "PATCH", "DELETE"])
    @require_auth
    def asset_inventory(asset_id=None):
        uid = get_current_user_id()
        if uid is None:
            return jsonify(error="Invalid account"), 401

        with db.session() as conn:
            if request.method == "GET":
                assets = []
                by_ip = {}

                for row in conn.execute(
                    "SELECT * FROM asset_inventory WHERE user_id = ? ORDER BY id",
                    (uid,),
                ):
                    asset = dict(
                        json.loads(row["profile"]),
                        id=row["id"],
                        ip=row["ip"],
                        online=row["online"],
                        created=row["created"],
                        events=[],
                        incidents=[],
                        risk=None,
                    )
                    assets.append(asset)
                    by_ip[row["ip"]] = asset

                if not assets:
                    return jsonify(assets)

                # Remember which registered IPs appeared in each event.
                linked = {}
                for event in conn.execute("""
                    SELECT e.id, e.event_type, e.timestamp, e.source_ip, e.dest_ip
                    FROM events e
                    JOIN scan_sessions s ON s.id = e.scan_id
                    WHERE s.user_id = ?
                    ORDER BY julianday(e.timestamp) DESC, e.id DESC
                """, (uid,)):
                    matching_ips = {event["source_ip"], event["dest_ip"]} & by_ip.keys()
                    for ip in matching_ips:
                        by_ip[ip]["events"].append(dict(event))
                        linked.setdefault(event["id"], set()).add(ip)

                for incident in conn.execute("""
                    SELECT id, title, event_ids, risk_score
                    FROM incidents
                    WHERE user_id = ?
                    ORDER BY id DESC
                """, (uid,)):
                    try:
                        ids = json.loads(incident["event_ids"] or "[]")
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(ids, list):
                        continue

                    ips = set()
                    for event_id in ids:
                        if type(event_id) is int:
                            ips.update(linked.get(event_id, ()))

                    for ip in ips:
                        asset = by_ip[ip]
                        asset["incidents"].append({
                            "id": incident["id"],
                            "title": incident["title"],
                        })
                        score = incident["risk_score"]
                        if score is not None:
                            asset["risk"] = max(score, asset["risk"] or 0)

                return jsonify(assets)

            if request.method == "DELETE":
                cur = conn.execute(
                    "DELETE FROM asset_inventory WHERE id = ? AND user_id = ?",
                    (asset_id, uid),
                )
                if not cur.rowcount:
                    return jsonify(error="Asset not found"), 404
                return "", 204

            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify(error="Expected an asset object"), 400

            if request.method == "PATCH":
                if type(data.get("online")) is not bool:
                    return jsonify(error="Select online or offline"), 400
                cur = conn.execute(
                    "UPDATE asset_inventory SET online = ? WHERE id = ? AND user_id = ?",
                    (data["online"], asset_id, uid),
                )
            else:
                if any(not isinstance(data.get(k, ""), str) for k in FIELDS):
                    return jsonify(error="Invalid asset fields"), 400

                profile = {k: data.get(k, "").strip() for k in FIELDS}

                if not profile["name"] or profile["type"] not in TYPES:
                    return jsonify(error="Enter a name and select an asset type"), 400
                if profile["crit"] not in ("low", "medium", "high", "critical"):
                    return jsonify(error="Select a criticality"), 400
                if profile["sec"] not in ("unknown", "secure", "warning", "risk"):
                    return jsonify(error="Select a security status"), 400

                try:
                    ip = str(IPv4Address(profile.pop("ip")))
                except ValueError:
                    return jsonify(error="Enter a valid IPv4 address"), 400

                try:
                    if request.method == "POST":
                        cur = conn.execute("""
                            INSERT INTO asset_inventory(user_id, ip, profile, created)
                            VALUES (?, ?, ?, ?)
                        """, (
                            uid, ip, json.dumps(profile),
                            datetime.now(timezone.utc).isoformat(),
                        ))
                        return jsonify(id=cur.lastrowid), 201

                    cur = conn.execute("""
                        UPDATE asset_inventory SET ip = ?, profile = ?
                        WHERE id = ? AND user_id = ?
                    """, (ip, json.dumps(profile), asset_id, uid))
                except sqlite3.IntegrityError:
                    return jsonify(error="An asset with this IP already exists"), 409

            if not cur.rowcount:
                return jsonify(error="Asset not found"), 404
            return jsonify(id=asset_id)